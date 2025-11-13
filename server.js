const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const os = require('os');
const archiver = require('archiver');
const { randomUUID } = require('crypto');
const http = require('http');
const { Server } = require('socket.io');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet'); // HTTP হেডার সুরক্ষিত করার জন্য
const compression = require('compression'); // রেসপন্স Gzip করার জন্য
const nodemailer = require('nodemailer'); // ইমেইল পাঠানোর জন্য
const crypto = require('crypto'); // র্যান্ডম পাসওয়ার্ড তৈরির জন্য
require('dotenv').config(); // .env ফাইল থেকে গোপন তথ্য লোড করার জন্য

// --- গ্লোবাল ভেরিয়েবল ---
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const BATCH_INTERVAL_MS = 10000; // ১০ সেকেন্ড পর পর ডাটাবেসে সেভ হবে
const FILTER_INTERVAL_MS = 10 * 60 * 1000; // ১০ মিনিট
const OFFLINE_THRESHOLD_MS = 10 * 60 * 1000; // ১০ মিনিট (অফলাইন হওয়ার সময়)
const CHECK_OFFLINE_INTERVAL_MS = 1 * 60 * 1000; // প্রতি ১ মিনিটে চেক করবে

let espDataBuffer = []; // ESP32 থেকে আসা ডেটা এখানে জমা হবে
const backupJobs = new Map(); // jobId -> { status, progress, tmpDir, zipPath, error }

// --- অ্যাপ এবং সার্ভার সেটআপ ---
const app = express();
const port = process.env.PORT || 3002;
const http_server = http.createServer(app); // socket.io এর জন্য http সার্ভার
const io = new Server(http_server);

// --- Nodemailer Transport (ইমেইল পাঠানোর সেটআপ) ---
let mailTransporter;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    secure: process.env.EMAIL_SECURE === 'true', // true for 465, false for other ports
    auth: {
      user: process.env.EMAIL_USER, // .env থেকে আপনার ইমেইল
      pass: process.env.EMAIL_PASS, // .env থেকে আপনার অ্যাপ পাসওয়ার্ড
    },
  });
  
  mailTransporter.verify((error, success) => {
    if (error) {
      console.warn('[Nodemailer Error] ইমেইল কনফিগারেশন সঠিক নয়। "Forgot Password" কাজ করবে না:', error.message);
    } else {
      console.log('[Nodemailer Success] ইমেইল সার্ভার প্রস্তুত। "Forgot Password" কাজ করবে।');
    }
  });
} else {
  console.warn('[Nodemailer Info] EMAIL_USER বা EMAIL_PASS .env ফাইলে সেট করা নেই। "Forgot Password" কাজ করবে না।');
}


// --- Simple JWT auth middleware ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) return res.status(401).send({ success: false, message: 'Authorization header missing' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).send({ success: false, message: 'Invalid authorization format' });

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // payload should contain userId
    return next();
  } catch (err) {
    return res.status(401).send({ success: false, message: 'Invalid or expired token' });
  }
}

// --- প্রোডাকশন মিডলওয়্যার ---
app.use(helmet()); // নিরাপত্তা বৃদ্ধি
app.use(compression()); // পারফরম্যান্স বৃদ্ধি
app.use(cors()); // CORS অনুমতি
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// --- MongoDB কানেকশন ---
const uri = process.env.MONGODB_URI; // .env ফাইল থেকে URI লোড করা
if (!uri) {
  throw new Error('MONGODB_URI is not defined in .env file');
}
const client = new MongoClient(uri);

// --- হেল্পার ফাংশন (ডাটাবেসের বাইরে) ---

/**
 * [ফাস্ট সিঙ্ক]
 * এই ফাংশনটি বাফারে জমা হওয়া সব ডেটা একসাথে ডাটাবেসে ইনসার্ট করে
 * এবং রিয়েল-টাইমে 'devicesCollection' আপডেট করে।
 */
async function flushDataBuffer(collection, devicesCollection) {
  if (espDataBuffer.length === 0) {
    return; // বাফার খালি থাকলে কিছু করার নেই
  }

  const dataToInsert = [...espDataBuffer];
  espDataBuffer = [];

  console.log(`[Batch Insert] Inserting ${dataToInsert.length} documents...`);

  try {
    // ১. মূল ডেটা EspCollection-এ ইনসার্ট করা
    await collection.insertMany(dataToInsert, { ordered: false });
    console.log(`[Batch Insert] Successfully inserted ${dataToInsert.length} documents.`);
    
    // নতুন ডেটা ক্লায়েন্টদের কাছে পাঠানো (socket.io)
    io.emit('new-data', dataToInsert);

    // --- [ফাস্ট সিঙ্ক] রিয়েল-টাইম ডিভাইস স্ট্যাটাস আপডেট ---
    const lastSeenUpdates = new Map();
    for (const data of dataToInsert) {
      if (data.uid) {
        // [পরিবর্তন] lastSeen-এর জন্য data.timestamp-কে প্রাধান্য দেওয়া হবে
        const newTime = data.timestamp || data.receivedAt || new Date(); 
        const existing = lastSeenUpdates.get(data.uid);
        
        // শুধুমাত্র সর্বশেষ ডেটা এবং সময় সংরক্ষণ করা
        if (!existing || newTime >= existing.time) {
          lastSeenUpdates.set(data.uid, { 
            time: newTime, 
            data: { // সর্বশেষ সেন্সর ডেটা
              temperature: data.temperature,
              water_level: data.water_level,
              rainfall: data.rainfall
            } 
          });
        }
      }
    }

    if (lastSeenUpdates.size > 0) {
      const bulkOps = [];
      const updatedDeviceUIDs = [];

      lastSeenUpdates.forEach((update, uid) => {
        updatedDeviceUIDs.push(uid);
        bulkOps.push({
          updateOne: {
            filter: { uid: uid },
            update: {
              $set: {
                lastSeen: update.time,
                status: 'online', // যখনই ডেটা পাই, তখনই 'online'
                data: update.data // সর্বশেষ সেন্সর ডেটা আপডেট করা
              },
              $setOnInsert: { // যদি ডিভাইসটি আগে না থাকে
                uid: uid,
                addedAt: new Date(),
                location: null, // নতুন ডিভাইসে ডিফল্ট লোকেশন
                name: null
              }
            },
            upsert: true // যদি uid না থাকে, নতুন ডকুমেন্ট তৈরি করবে
          }
        });
      });

      // ২. devicesCollection-এ স্ট্যাটাস এবং নতুন ডিভাইস যোগ করা
      await devicesCollection.bulkWrite(bulkOps, { ordered: false });
      console.log(`[Device Status] Fast Sync: Updated ${bulkOps.length} devices in devicesCollection.`);
      
      // ডিভাইস স্ট্যাটাস আপডেট ক্লায়েন্টদের কাছে পাঠানো (socket.io)
      io.emit('device-status-updated', updatedDeviceUIDs);
    }
    // --- ডিভাইস স্ট্যাটাস আপডেট শেষ ---

  } catch (error) {
    console.error("[Batch Insert] Failed to insert data or update device status:", error.message);
  }
}

/**
 * [স্লো সিঙ্ক - ফলব্যাক]
 * EspCollection থেকে সব ইউনিক UID খুঁজে বের করে
 * devicesCollection-এ সেভ করে।
 */
async function syncAllDevices(EspCollection, devicesCollection) {
  try {
    console.log('[Device Sync Job] Starting 10-min device list sync job...');
    
    // ১. EspCollection থেকে সব ইউনিক UID বের করা (ধীর)
    const uids = await EspCollection.distinct('uid');
    
    if (!uids || uids.length === 0) {
      console.log('[Device Sync Job] No UIDs found in data collection.');
      return;
    }

    // ২. devicesCollection-এ 'upsert' করার জন্য প্রস্তুত করা
    const bulkOps = uids.map(uid => ({
      updateOne: {
        filter: { uid: uid },
        update: { 
          $setOnInsert: { // শুধু নতুন হলে সেট করবে
            uid: uid, 
            addedAt: new Date(),
            status: 'unknown', // আমরা শুধু জানি এটি বিদ্যমান, স্ট্যাটাস জানি না
            lastSeen: null,
            data: {} // নতুন ডিভাইসে খালি ডেটা
          } 
        },
        upsert: true // যদি UID না থাকে, তবে নতুন ডকুমেন্ট তৈরি করবে
      }
    }));

    // ৩. বাল্ক অপারেশন চালানো
    if (bulkOps.length > 0) {
      const result = await devicesCollection.bulkWrite(bulkOps, { ordered: false });
      console.log(`[Device Sync Job] Job finished. Found ${uids.length} unique devices. New devices added: ${result.upsertedCount}, Already existed: ${result.matchedCount}`);
    } else {
      console.log('[Device Sync Job] No new devices to add.');
    }

  } catch (error) {
    console.error('[Device Sync Job] Error in 10-min sync job:', error);
  }
}

/**
 * [অফলাইন চেকার]
 * যে ডিভাইসগুলো 'online' স্ট্যাটাসে আছে কিন্তু
 * OFFLINE_THRESHOLD_MS (১০ মিনিট) ধরে কোনো ডেটা পাঠায়নি,
 * সেগুলোকে 'offline' সেট করে।
 */
async function checkOfflineDevices(devicesCollection) {
  console.log('[Offline Check] Running job to find offline devices...');
  try {
    // ১০ মিনিট আগের সময়
    const thresholdTime = new Date(Date.now() - OFFLINE_THRESHOLD_MS);
    
    // সেই সব ডিভাইস খুঁজুন যারা 'online' কিন্তু 'lastSeen' ১০ মিনিটের বেশি পুরনো
    const devicesToUpdate = await devicesCollection.find(
      { 
        status: 'online', 
        lastSeen: { $lt: thresholdTime } // lastSeen < (বর্তমান সময় - ১০ মিনিট)
      },
      { projection: { uid: 1 } }
    ).toArray();

    if (devicesToUpdate.length === 0) {
      // অফলাইন করার মতো কোনো ডিভাইস নেই
      return;
    }

    const uidsToUpdate = devicesToUpdate.map(d => d.uid);

    const result = await devicesCollection.updateMany(
      { uid: { $in: uidsToUpdate } },
      { 
        $set: { status: 'offline' } 
      }
    );

    if (result.modifiedCount > 0) {
      console.log(`[Offline Check] Marked ${result.modifiedCount} devices as offline.`);
      // অফলাইন স্ট্যাটাস ক্লায়েন্টদের কাছে পাঠানো (socket.io)
      io.emit('device-status-updated', uidsToUpdate);
    }
  } catch (error) {
    console.error('[Offline Check] Error checking for offline devices:', error.message);
  }
}


/**
 * পুরনো ব্যাকআপ জব এবং ফাইল মুছে ফেলার জন্য
 */
function cleanupOldBackupJobs() {
  const NOW = Date.now();
  const MAX_AGE_MS = 60 * 60 * 1000; // ১ ঘণ্টা

  backupJobs.forEach((job, jobId) => {
    const jobTime = job.finishedAt ? job.finishedAt.getTime() : 0;
    
    // 'done' বা 'error' স্ট্যাটাসের জব যা ১ ঘণ্টার বেশি পুরনো
    if ((job.status === 'done' || job.status === 'error') && (NOW - jobTime > MAX_AGE_MS)) {
        console.log(`[Backup Cleanup] Deleting old job ${jobId}`);
        if (job.tmpDir) {
          try {
            fs.rmSync(job.tmpDir, { recursive: true, force: true });
          } catch(e) {
            console.warn(`[Backup Cleanup] Failed to delete tmpDir: ${job.tmpDir}`, e.message);
          }
        }
        backupJobs.delete(jobId);
    }
  });
}

// --- প্রধান async ফাংশন ---
async function run() {
  try {
    await client.connect();
    console.log('DB connected');

    const db = client.db('Esp32data');

    // --- কালেকশন ডিফাইন করা ---
    const EspCollection = db.collection('espdata2'); 
    const devicesCollection = db.collection('devices'); // ডিভাইস স্ট্যাটাস এবং তথ্যের জন্য
    const usersCollection = db.collection('users'); // ইউজার অথেন্টিকেশন

    // --- ইনডেক্সিং (সুপারিশ) ---
    // db.espdata2.createIndex({ uid: 1, timestamp: -1 })
    // db.devices.createIndex({ uid: 1 }, { unique: true })
    // db.users.createIndex({ email: 1 }, { unique: true })

    // --- টাইমার চালু করা ---
    
    // [ফাস্ট সিঙ্ক] প্রতি ১০ সেকেন্ড পর পর বাফার খালি করা
    setInterval(() => flushDataBuffer(EspCollection, devicesCollection), BATCH_INTERVAL_MS);

    // [স্লো সিঙ্ক] প্রতি ১০ মিনিটে ডিভাইস লিস্ট আপডেটের টাইমার
    setInterval(() => syncAllDevices(EspCollection, devicesCollection), FILTER_INTERVAL_MS);

    // [অফলাইন চেকার] প্রতি ১ মিনিটে অফলাইন ডিভাইস চেক করা
    setInterval(() => checkOfflineDevices(devicesCollection), CHECK_OFFLINE_INTERVAL_MS);

    // প্রতি ১৫ মিনিটে পুরনো ব্যাকআপ জব মুছে ফেলা
    setInterval(cleanupOldBackupJobs, 15 * 60 * 1000);

    // সার্ভার চালু হলেই একবার 'স্লো সিঙ্ক' চালানোর জন্য
    console.log('Running initial device list sync job on startup...');
    syncAllDevices(EspCollection, devicesCollection);

    // --- অ্যাডমিন চেক হেল্পার (run-এর ভেতরে) ---
    async function ensureAdmin(req, res) {
      try {
        const userId = req.user && req.user.userId;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });
        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
        const isAdminEnv = process.env.ADMIN_EMAIL && user && user.email === process.env.ADMIN_EMAIL;
        if (user && (user.isAdmin === true || isAdminEnv)) return { ok: true, user };
        return res.status(403).send({ success: false, message: 'Admin access required' });
      } catch (error) {
        console.error('Admin check error:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    }


    // -------------------------
    // --- রুট (Routes) ---
    // -------------------------

    // --- IoT Data Routes ---

    // !! ক্রিটিক্যাল: ESP32 থেকে ডেটা গ্রহণ (POST) - ব্যাচ মোডে (UTC টাইম)
    app.post('/api/esp32pp', async (req, res) => {
      try {
        const data = req.body;
        data.timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
        data.receivedAt = new Date(); // সার্ভার রিসিভ টাইম (UTC)
        espDataBuffer.push(data);
        res.status(200).send({ message: 'Data accepted and queued.' });
      } catch (error) {
        res.status(400).send({ message: 'Invalid data format' });
      }
    });

    // ESP32 থেকে ডেটা গ্রহণ (POST) - বাংলাদেশ টাইমসহ
    app.post('/api/esp32p', async (req, res) => {
      try {
        const data = req.body;
        
        // সার্ভারের বর্তমান বাংলাদেশ (+6) সময় গণনা
        const bdTime = new Date(Date.now() + (6 * 60 * 60 * 1000));
        data.receivedAt = bdTime; // সার্ভার রিসিভ টাইম (BDT)

        // ESP32 থেকে আসা টাইমস্ট্যাম্পকে বাংলাদেশ (+6) টাইমজোন হিসেবে গণ্য করা
        if (data.timestamp && typeof data.timestamp === 'string') {
          // ইনপুট "2025-11-06 02:44:11"
          const isoString = data.timestamp.replace(' ', 'T') + "+06:00";
          data.timestamp = new Date(isoString);
        } else {
          // যদি ESP কোনো টাইম না পাঠায়, তবে সার্ভারের BDT টাইম ব্যবহার করা
          data.timestamp = bdTime;
        }

        espDataBuffer.push(data);
        res.status(200).send({ message: 'Data accepted and queued.' });
      } catch (error) {
        console.error("Error in /api/esp32p:", error.message);
        res.status(400).send({ message: 'Invalid data format' });
      }
    });


    // ESP32 থেকে ডেটা পড়া (GET) - সব ডেটা
    app.get('/api/esp32', async (req, res) => {
      const query = {};
      const cursor = EspCollection.find(query);
      const Data = await cursor.toArray();
      res.send(Data);
    });

    // --- Public Data Routes ---

    // GET /api/device/data
    // সর্বশেষ N (default 300) ডেটা পয়েন্ট
    app.get('/api/device/data', async (req, res) => {
      try {
        const { uid, limit } = req.query || {};
        const lim = Math.min(1000, Math.max(1, parseInt(limit, 10) || 300));
        const q = {};
        if (uid) q.uid = String(uid);

        const docs = await EspCollection.find(q)
          .sort({ timestamp: -1 })
          .limit(lim)
          .project({ uid: 1, temperature: 1, water_level: 1, rainfall: 1, timestamp: 1, _id: 0 })
          .toArray();

        return res.send(docs);
      } catch (error) {
        console.error('Error in /api/device/data (GET):', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/device/data-by-range
    // তারিখ অনুযায়ী ডেটা
    app.post('/api/device/data-by-range', async (req, res) => {
      try {
        const { uid, start, end, limit } = req.body || {};
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        function parseDate(s, fallback) {
          if (!s) return fallback;
          const normalized = String(s).trim().replace(' ', 'T');
          const d = new Date(normalized);
          if (isNaN(d.getTime())) return null;
          return d;
        }

        const startDate = parseDate(start, new Date(0));
        const endDate = parseDate(end, new Date());
        if (!startDate || !endDate) return res.status(400).send({ success: false, message: 'Invalid start or end date' });

        const lim = Math.min(20000, Math.max(1, parseInt(limit, 10) || 10000));

        const query = { uid: String(uid), timestamp: { $gte: startDate, $lte: endDate } };
        const docs = await EspCollection.find(query)
          .sort({ timestamp: 1 })
          .limit(lim)
          .project({ uid: 1, temperature: 1, water_level: 1, rainfall: 1, timestamp: 1, _id: 0 })
          .toArray();

        return res.send(docs);
      } catch (error) {
        console.error('Error in /api/device/data-by-range:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // --- Async Backup Job Routes ---

    // POST /api/backup/start
    // ব্যাকআপ জব শুরু করার জন্য
    app.post('/api/backup/start', async (req, res) => {
      try {
        const { uid } = req.body || {};
        const q = {};
        if (uid) q.uid = String(uid);

        const jobId = randomUUID();
        const tmpDir = path.join(os.tmpdir(), `esp-backup-${jobId}`);
        fs.mkdirSync(tmpDir, { recursive: true });
        const jsonPath = path.join(tmpDir, 'espdata.json');
        const zipPath = path.join(tmpDir, 'espdata.zip');

        const job = { status: 'pending', progress: 0, tmpDir, jsonPath, zipPath, error: null };
        backupJobs.set(jobId, job);

        // run export in background
        (async () => {
          try {
            job.status = 'counting';
            const total = await EspCollection.countDocuments(q);
            job.total = total;

            job.status = 'exporting';
            const out = fs.createWriteStream(jsonPath, { encoding: 'utf8' });
            out.write('[');
            let first = true;
            let written = 0;
            const cursor = EspCollection.find(q).sort({ timestamp: 1 });

            for await (const doc of cursor) {
              const copy = { ...doc };
              if (copy._id) copy._id = copy._id.toString();
              if (copy.timestamp) copy.timestamp = copy.timestamp.toISOString();
              if (copy.receivedAt) copy.receivedAt = copy.receivedAt.toISOString();
              if (!first) out.write(',\n');
              out.write(JSON.stringify(copy));
              first = false;
              written++;

              if (total > 0) {
                const pct = Math.floor((written / total) * 100);
                if (pct !== job.progress) job.progress = pct;
              }
            }
            out.write(']');
            out.end();
            await new Promise((resolve, reject) => {
              out.on('finish', resolve);
              out.on('error', reject);
            });

            job.status = 'zipping';
            const output = fs.createWriteStream(zipPath);
            const archive = archiver('zip', { zlib: { level: 9 } });
            archive.pipe(output);
            archive.file(jsonPath, { name: 'espdata.json' });
            await archive.finalize();
            await new Promise((resolve, reject) => {
              output.on('close', resolve);
              output.on('error', reject);
            });

            job.status = 'done';
            job.progress = 100;
            job.zipPath = zipPath;
            job.finishedAt = new Date();
          } catch (err) {
            console.error('Backup job error', jobId, err);
            job.status = 'error';
            job.error = err && (err.message || String(err));
            job.finishedAt = new Date();
          }
        })();

        return res.send({ jobId });
      } catch (error) {
        console.error('Error starting backup job:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // SSE endpoint to stream progress updates: GET /api/backup/status/:jobId
    app.get('/api/backup/status/:jobId', (req, res) => {
      const { jobId } = req.params;
      const job = backupJobs.get(jobId);
      if (!job) return res.status(404).send({ success: false, message: 'Job not found' });

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders && res.flushHeaders();

      const iv = setInterval(() => {
        const j = backupJobs.get(jobId);
        if (!j) {
          clearInterval(iv);
          return res.end();
        }
        res.write(`event: progress\ndata: ${JSON.stringify({ status: j.status, progress: j.progress, error: j.error || null })}\n\n`);

        if (j.status === 'done' || j.status === 'error') {
          res.write(`event: done\ndata: ${JSON.stringify({ status: j.status, download: j.status === 'done' ? `/api/backup/download/${jobId}` : null, error: j.error || null })}\n\n`);
          clearInterval(iv);
          return res.end();
        }
      }, 1000);

      req.on('close', () => clearInterval(iv));
    });

    // GET /api/backup/download/:jobId
    app.get('/api/backup/download/:jobId', (req, res) => {
      const { jobId } = req.params;
      const job = backupJobs.get(jobId);
      if (!job) return res.status(404).send({ success: false, message: 'Job not found' });
      if (job.status !== 'done' || !job.zipPath) return res.status(400).send({ success: false, message: 'Job not ready' });

      res.download(job.zipPath, 'espdata.zip', (err) => {
        try {
          fs.rmSync(job.tmpDir, { recursive: true, force: true });
        } catch (e) {
          console.warn('Failed to cleanup backup tmpDir after download:', e && e.message);
        }
        backupJobs.delete(jobId);
        if (err) console.error('Error sending backup download:', err);
      });
    });

    // --- User Auth Routes ---

    // POST /api/user/register
    app.post('/api/user/register', async (req, res) => {
      try {
        const { name, email, password } = req.body || {};
        if (!name || !email || !password) {
          return res.status(400).send({ success: false, message: 'name, email and password are required' });
        }
        const normalizedEmail = String(email).trim().toLowerCase();
        const existing = await usersCollection.findOne({ email: normalizedEmail });
        if (existing) {
          return res.status(400).send({ success: false, message: 'Email already registered' });
        }
        const passwordHash = await bcrypt.hash(String(password), 10);
        const newUser = {
          name: String(name).trim(),
          email: normalizedEmail,
          passwordHash,
          devices: [],
          createdAt: new Date(),
          address: null, // নতুন ফিল্ড
          mobile: null   // নতুন ফিল্ড
        };
        await usersCollection.insertOne(newUser);
        return res.send({ success: true, message: 'User registered successfully' });
      } catch (error) {
        console.error('Error in /api/user/register:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/user/login
    app.post('/api/user/login', async (req, res) => {
      try {
        const { email, password } = req.body || {};
        if (!email || !password) return res.status(400).send({ success: false, message: 'email and password are required' });
        
        const normalizedEmail = String(email).trim().toLowerCase();
        const user = await usersCollection.findOne({ email: normalizedEmail });
        if (!user) return res.status(401).send({ success: false, message: 'Invalid credentials' });
        
        const ok = await bcrypt.compare(String(password), user.passwordHash);
        if (!ok) return res.status(401).send({ success: false, message: 'Invalid credentials' });
        
        const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        return res.send({ success: true, token });
      } catch (error) {
        console.error('Error in /api/user/login:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/user/password/forgot (Public)
    // পাসওয়ার্ড ভুলে গেলে ইমেইলে নতুন পাসওয়ার্ড পাঠানো
    app.post('/api/user/password/forgot', async (req, res) => {
      if (!mailTransporter) {
        return res.status(500).send({ success: false, message: 'Email service is not configured on this server.' });
      }

      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).send({ success: false, message: 'Email is required.' });
        }
        
        const normalizedEmail = String(email).trim().toLowerCase();
        const user = await usersCollection.findOne({ email: normalizedEmail });

        if (!user) {
          // ইউজার না থাকলেও, নিরাপত্তার জন্য "ইমেইল পাঠানো হয়েছে" দেখানো
          return res.send({ success: true, message: 'If an account with this email exists, a new password has been sent.' });
        }

        // নতুন র্যান্ডম পাসওয়ার্ড তৈরি
        const newPassword = crypto.randomBytes(6).toString('hex'); // 12-character password
        const passwordHash = await bcrypt.hash(newPassword, 10);

        // ডাটাবেসে নতুন পাসওয়ার্ড হ্যাশ সেভ করা
        await usersCollection.updateOne(
          { _id: user._id },
          { $set: { passwordHash: passwordHash } }
        );

        // ইউজারকে ইমেইল পাঠানো
        await mailTransporter.sendMail({
          from: `"ESP App Admin" <${process.env.EMAIL_USER}>`,
          to: user.email,
          subject: 'Your New Password for ESP App',
          text: `Hello ${user.name},\n\nYour password has been reset. Your new temporary password is: ${newPassword}\n\nPlease login immediately and change this password.\n\nThank you,\nESP App Team`,
          html: `<p>Hello ${user.name},</p><p>Your password has been reset. Your new temporary password is: <b>${newPassword}</b></p><p>Please login immediately and change this password.</p><p>Thank you,<br>ESP App Team</p>`,
        });

        res.send({ success: true, message: 'If an account with this email exists, a new password has been sent.' });

      } catch (error) {
        console.error('Error in /api/user/password/forgot:', error);
        // ইউজারকে বিস্তারিত এরর না দেখিয়ে জেনেরিক মেসেজ পাঠানো
        res.status(500).send({ success: false, message: 'An error occurred while trying to reset the password.' });
      }
    });


    // --- User-Protected Routes ---

    // GET /api/device/list (যেকোনো লগইন করা ইউজার)
    // devicesCollection থেকে সব ডিভাইসের লিস্ট দেখাবে
    app.get('/api/device/list', authenticateJWT, async (req, res) => {
      try {
        // _id বাদে সব ডিভাইসের তথ্য পাঠানো
        const devices = await devicesCollection.find({})
          .project({ _id: 0, uid: 1, name: 1, location: 1, status: 1, lastSeen: 1, addedAt: 1, data: 1 })
          .toArray();
          
        res.send(devices);
      } catch (error) {
        console.error('Error in /api/device/list:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/user/device/add (protected)
    app.post('/api/user/device/add', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        const { uid } = req.body || {};
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });
        if (!uid || String(uid).trim() === '') return res.status(400).send({ success: false, message: 'uid is required' });

        await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $addToSet: { devices: String(uid).trim() } }
        );
        return res.send({ success: true, message: 'Device added to user' });
      } catch (error) {
        console.error('Error in /api/user/device/add:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // DELETE /api/user/device/remove (protected)
    app.delete('/api/user/device/remove', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        const { uid } = req.body || {};
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });
        if (!uid || String(uid).trim() === '') return res.status(400).send({ success: false, message: 'uid is required' });

        await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $pull: { devices: String(uid).trim() } }
        );
        return res.send({ success: true, message: 'Device removed from user' });
      } catch (error) {
        console.error('Error in /api/user/device/remove:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/user/devices (protected)
    // ইউজারের ডিভাইস লিস্ট এবং সেগুলোর স্ট্যাটাস
    app.get('/api/user/devices', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (!user) return res.status(404).send({ success: false, message: 'User not found' });

        const uDevices = user.devices || [];
        if (uDevices.length === 0) return res.send([]);

        const found = await devicesCollection.find({ uid: { $in: uDevices } }).toArray();
        const result = uDevices.map((uid) => {
          const d = found.find((x) => x.uid === uid);
          return { 
            uid, 
            name: d?.name, 
            location: d?.location, 
            status: d ? d.status || 'offline' : 'offline', 
            lastSeen: d ? d.lastSeen : null,
            data: d ? d.data : {} // সর্বশেষ ডেটা যোগ করা
          };
        });

        return res.send(result);
      } catch (error) {
        console.error('Error in /api/user/devices:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/user/device/:uid/data (protected)
    // ইউজারের নির্দিষ্ট ডিভাইসের ডেটা
    app.get('/api/user/device/:uid/data', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        const uid = req.params.uid;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (!user) return res.status(404).send({ success: false, message: 'User not found' });
        if (!user.devices || !user.devices.includes(uid)) {
          return res.status(403).send({ success: false, message: 'Forbidden: device not assigned to user' });
        }

        const { start, end, limit } = req.query || {};
        const lim = Math.min(5000, Math.max(1, parseInt(limit, 10) || 500));
        let startDate, endDate;

        if (start && end) {
          startDate = new Date(start);
          endDate = new Date(end);
          endDate.setHours(23, 59, 59, 999);
        } else {
          // ডিফল্ট: শেষ ২৪ ঘণ্টা
          endDate = new Date();
          startDate = new Date(endDate.getTime() - (24 * 60 * 60 * 1000));
        }

        const query = { uid, timestamp: { $gte: startDate, $lte: endDate } };
        const docs = await EspCollection.find(query)
          .sort({ timestamp: -1 }) // চার্টের জন্য সর্বশেষ ডেটা আগে
          .limit(lim)
          .project({ temperature: 1, water_level: 1, rainfall: 1, timestamp: 1, _id: 0 })
          .toArray();

        return res.send(docs.reverse()); // চার্টে সঠিক অর্ডারের জন্য reverse()
      } catch (error) {
        console.error('Error in /api/user/device/:uid/data:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/user/profile (protected)
    // ইউজারের প্রোফাইল তথ্য
    app.get('/api/user/profile', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const user = await usersCollection.findOne(
          { _id: new ObjectId(userId) },
          { projection: { passwordHash: 0 } } // পাসওয়ার্ড হ্যাশ বাদ দিয়ে
        );

        if (!user) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }

        // ইউজার অ্যাডমিন কিনা তা চেক করা (ডাবল চেক)
        const isAdminEnv = process.env.ADMIN_EMAIL && user.email === process.env.ADMIN_EMAIL;
        user.isAdmin = (user.isAdmin === true || isAdminEnv);
        
        res.send(user);
      } catch (error) {
        console.error('Error in /api/user/profile:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });
    
    // GET /api/user/profile2 (protected)
    // ইউজারের প্রোফাইল তথ্য (টেস্ট রুট)
    app.get('/api/user/profile2', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const user = await usersCollection.findOne(
          { _id: new ObjectId(userId) },
          { projection: { passwordHash: 0 } } // পাসওয়ার্ড হ্যাশ বাদ দিয়ে
        );

        if (!user) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }

        // ইউজার অ্যাডমিন কিনা তা চেক করা (ডাবল চেক)
        const isAdminEnv = process.env.ADMIN_EMAIL && user.email === process.env.ADMIN_EMAIL;
        user.isAdmin = (user.isAdmin === true || isAdminEnv);
        
        // শুধু একটি ভিন্ন বার্তা যোগ করা হলো
        res.send({ message: "Profile from route /api/user/profile2", ...user });
      } catch (error) {
        console.error('Error in /api/user/profile2:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/user/profile/update (protected)
    // ইউজারের প্রোফাইল (নাম, ঠিকানা, মোবাইল) আপডেট করা
    app.post('/api/user/profile/update', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const { name, address, mobile } = req.body;
        const fieldsToUpdate = {};

        // ইউজার শুধু সেই ফিল্ড পাঠাবে যা সে আপডেট করতে চায়
        if (name !== undefined) fieldsToUpdate.name = String(name).trim();
        if (address !== undefined) fieldsToUpdate.address = String(address).trim();
        if (mobile !== undefined) fieldsToUpdate.mobile = String(mobile).trim();

        if (Object.keys(fieldsToUpdate).length === 0) {
          return res.status(400).send({ success: false, message: 'No fields to update.' });
        }

        const result = await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: fieldsToUpdate }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }

        res.send({ success: true, message: 'Profile updated successfully.' });

      } catch (error) {
        console.error('Error in /api/user/profile/update:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/user/password/change (protected)
    // ইউজারের পাসওয়ার্ড পরিবর্তন করা
    app.post('/api/user/password/change', authenticateJWT, async (req, res) => {
      try {
        const userId = req.user && req.user.userId;
        if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) {
          return res.status(400).send({ success: false, message: 'Old password and new password are required.' });
        }

        const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
        if (!user) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }

        // পুরনো পাসওয়ার্ড চেক করা
        const isMatch = await bcrypt.compare(String(oldPassword), user.passwordHash);
        if (!isMatch) {
          return res.status(401).send({ success: false, message: 'Invalid old password.' });
        }

        // নতুন পাসওয়ার্ড হ্যাশ করে সেভ করা
        const newPasswordHash = await bcrypt.hash(String(newPassword), 10);
        await usersCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { passwordHash: newPasswordHash } }
        );

        res.send({ success: true, message: 'Password changed successfully.' });

      } catch (error) {
        console.error('Error in /api/user/password/change:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });


    // --- Admin-Protected Routes ---

    // POST /api/filter/device (অ্যাডমিন রুট)
    // ম্যানুয়ালি ১০-মিনিটের "স্লো সিঙ্ক" জবটি ট্রিগার করার জন্য
    app.post('/api/filter/device', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return; // অ্যাডমিন কিনা চেক করা

      try {
        console.log('[API Trigger] Manually running device list sync job...');
        await syncAllDevices(EspCollection, devicesCollection);
        res.send({ success: true, message: 'Device list sync job triggered and completed successfully.' });
      } catch (error) {
        console.error('Error in /api/filter/device route:', error);
        res.status(500).send({ success: false, message: 'Job failed to run.' });
      }
    });

    // PUT /api/device/:uid (অ্যাডমিন রুট)
    // একটি ডিভাইসের লোকেশন বা নাম আপডেট করার জন্য
    app.put('/api/device/:uid', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const { uid } = req.params;
        const { location, name } = req.body;

        if (location === undefined && name === undefined) {
          return res.status(400).send({ success: false, message: 'location বা name প্রয়োজন' });
        }

        const updateFields = {};
        if (location !== undefined) updateFields.location = location;
        if (name !== undefined) updateFields.name = name;

        const result = await devicesCollection.updateOne(
          { uid: uid },
          { $set: updateFields }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ success: false, message: 'Device not found.' });
        }
        if (result.modifiedCount === 0 && result.matchedCount === 1) {
          return res.send({ success: true, message: 'No changes detected.' });
        }
        
        res.send({ success: true, message: `Device ${uid} updated successfully.` });
      } catch (error) {
        console.error('Error in /api/device/:uid (PUT):', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/admin/devices
    // সব ডিভাইস এবং তাদের মালিকদের লিস্ট
    app.get('/api/admin/devices', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const devices = await devicesCollection.aggregate([
          {
            $lookup: {
              from: 'users',
              let: { device_uid: '$uid' },
              pipeline: [
                { $match: { $expr: { $in: ['$$device_uid', '$devices'] } } },
                { $project: { name: 1, email: 1 } }
              ],
              as: 'owners'
            }
          },
          { $project: { _id: 0 } }
        ]).toArray();

        return res.send(devices);
      } catch (error) {
        console.error('Error in /api/admin/devices:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/admin/report
    // ডেটা রিপোর্ট (মাসিক, দৈনিক, বার্ষিক)
    app.get('/api/admin/report', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;
      try {
        const { period = 'monthly', year } = req.query || {};
        const match = {};
        if (year) {
          const y = parseInt(year, 10);
          if (!isNaN(y)) {
            match.timestamp = { $gte: new Date(`${y}-01-01T00:00:00Z`), $lt: new Date(`${y + 1}-01-01T00:00:00Z`) };
          }
        }
        let pipeline = [];
        if (Object.keys(match).length) pipeline.push({ $match: match });
        if (period === 'daily') {
          pipeline.push({
            $group: {
              _id: { year: { $year: '$timestamp' }, month: { $month: '$timestamp' }, day: { $dayOfMonth: '$timestamp' } },
              avgTemp: { $avg: '$temperature' }, avgRain: { $avg: '$rainfall' }, count: { $sum: 1 }
            }
          });
          pipeline.push({ $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1 } });
          const raw = await EspCollection.aggregate(pipeline).toArray();
          const result = raw.map(r => ({ date: `${r._id.year}-${String(r._id.month).padStart(2,'0')}-${String(r._id.day).padStart(2,'0')}`, avgTemp: Number(r.avgTemp.toFixed(2)), avgRain: Number(r.avgRain.toFixed(2)), count: r.count }));
          return res.send(result);
        }
        if (period === 'yearly') {
          pipeline.push({
            $group: {
              _id: { year: { $year: '$timestamp' } },
              avgTemp: { $avg: '$temperature' }, avgRain: { $avg: '$rainfall' }, count: { $sum: 1 }
            }
          });
          pipeline.push({ $sort: { '_id.year': 1 } });
          const raw = await EspCollection.aggregate(pipeline).toArray();
          const result = raw.map(r => ({ year: r._id.year, avgTemp: Number(r.avgTemp.toFixed(2)), avgRain: Number(r.avgRain.toFixed(2)), count: r.count }));
          return res.send(result);
        }
        // default: monthly
        pipeline.push({
          $group: {
            _id: { year: { $year: '$timestamp' }, month: { $month: '$timestamp' } },
            avgTemp: { $avg: '$temperature' }, avgRain: { $avg: '$rainfall' }, count: { $sum: 1 }
          }
        });
        pipeline.push({ $sort: { '_id.year': 1, '_id.month': 1 } });
        const raw = await EspCollection.aggregate(pipeline).toArray();
        const monthNames = ['January','February','March','April','May','June','July','August','September','October','November','December'];
        const result = raw.map(r => ({ month: monthNames[r._id.month - 1], year: r._id.year, avgTemp: Number(r.avgTemp.toFixed(2)), avgRain: Number(r.avgRain.toFixed(2)), count: r.count }));
        return res.send(result);
      } catch (error) {
        console.error('Error in /api/admin/report:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/admin/stats
    // অ্যাডমিন ড্যাশবোর্ডের জন্য পরিসংখ্যান
    app.get('/api/admin/stats', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const totalDevices = await devicesCollection.countDocuments();
        const onlineDevices = await devicesCollection.countDocuments({ status: 'online' });
        const offlineDevices = totalDevices - onlineDevices;
        const totalDataPoints = await EspCollection.countDocuments();
        const todayStart = new Date();
        todayStart.setHours(0,0,0,0);
        const dataToday = await EspCollection.countDocuments({ timestamp: { $gte: todayStart } });

        return res.send({ totalDevices, onlineDevices, offlineDevices, totalDataPoints, dataToday });
      } catch (error) {
        console.error('Error in /api/admin/stats:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/admin/users
    // সমস্ত ইউজারদের তালিকা (অ্যাডমিন রুট)
    app.get('/api/admin/users', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const users = await usersCollection.find({})
          .project({ passwordHash: 0 }) // পাসওয়ার্ড হ্যাশ বাদ দিয়ে
          .toArray();
        res.send(users);
      } catch (error) {
        console.error('Error in /api/admin/users:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/v1/user/data/:id (অ্যাডমিন রুট)
    // নির্দিষ্ট ইউজারের তথ্য
    app.get('/api/v1/user/data/:id', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ success: false, message: 'Invalid user ID format' });
        }
        
        const user = await usersCollection.findOne(
          { _id: new ObjectId(id) },
          { projection: { passwordHash: 0 } }
        );

        if (!user) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }
        
        // অ্যাডমিন স্ট্যাটাস যোগ করা
        const isAdminEnv = process.env.ADMIN_EMAIL && user.email === process.env.ADMIN_EMAIL;
        user.isAdmin = (user.isAdmin === true || isAdminEnv);

        res.send(user);

      } catch (error) {
        console.error('Error in /api/v1/user/data/:id:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/admin/user/make-admin
    // একজন ইউজারকে অ্যাডমিন বানানো (অ্যাডমিন রুট)
    app.post('/api/admin/user/make-admin', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).send({ success: false, message: 'Email is required' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();
        const result = await usersCollection.updateOne(
          { email: normalizedEmail },
          { $set: { isAdmin: true } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }

        res.send({ success: true, message: `User ${normalizedEmail} has been made an admin.` });

      } catch (error) {
        console.error('Error in /api/admin/user/make-admin:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/admin/user/remove-admin
    // একজন ইউজারের অ্যাডমিন স্ট্যাটাস বাতিল করা (অ্যাডমিন রুট)
    app.post('/api/admin/user/remove-admin', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return;

      try {
        const { email } = req.body;
        if (!email) {
          return res.status(400).send({ success: false, message: 'Email is required' });
        }

        const normalizedEmail = String(email).trim().toLowerCase();

        // .env ফাইলে থাকা সুপার অ্যাডমিনকে রিমুভ করা যাবে না
        if (process.env.ADMIN_EMAIL && normalizedEmail === process.env.ADMIN_EMAIL) {
          return res.status(403).send({ success: false, message: 'Cannot remove the primary admin.' });
        }

        // একজন অ্যাডমিন নিজেকে রিমুভ করতে পারবে না
        if (check.user.email === normalizedEmail) {
          return res.status(403).send({ success: false, message: 'Admin cannot remove themselves.' });
        }

        const result = await usersCollection.updateOne(
          { email: normalizedEmail },
          { $set: { isAdmin: false } } // অথবা $unset: { isAdmin: 1 }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ success: false, message: 'User not found' });
        }

        res.send({ success: true, message: `User ${normalizedEmail}'s admin privileges have been revoked.` });

      } catch (error) {
        console.error('Error in /api/admin/user/remove-admin:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });


  } finally {
    // প্রোডাকশন সার্ভারে ক্লায়েন্ট বন্ধ করা উচিত নয়
    // await client.close();
  }
}
run().catch(console.dir);

// Socket.io কানেকশন
io.on('connection', (socket) => {
  console.log('A user connected via socket.io');
  
  // আপনি এখানে রিয়েল-টাইম ডেটা পাঠাতে পারেন
  // io.emit('new-data', data);

  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// রুট পেইজ
app.get("/", (req, res) => {
  res.send(`<h1 style="text-align: center; color: green;">Max it Server (Production Ready) is Running at ${port}</h1>`);
});

// সার্ভার চালু করা
http_server.listen(port, () => {
  console.log(`Max it Production server running at: ${port}`);
  console.log(`Current server time: ${new Date().toLocaleString('en-US', { timeZone: 'Asia/Dhaka' })} (Asia/Dhaka)`);
});
