const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // আপনি এটি ইম্পোর্ট করেছেন, তাই আমি রেখে দিয়েছি
const multer = require('multer');
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
require('dotenv').config(); // .env ফাইল থেকে গোপন তথ্য লোড করার জন্য

const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';

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

// --- অ্যাপ এবং সার্ভার সেটআপ ---
const app = express();
const port = process.env.PORT || 3002;
const http_server = http.createServer(app); // socket.io এর জন্য http সার্ভার
const io = new Server(http_server);

// --- প্রোডাকশন মিডলওয়্যার ---
app.use(helmet()); // নিরাপত্তা বৃদ্ধি
app.use(compression()); // পারফরম্যান্স বৃদ্ধি

// --- CORS ফিক্স ---
// টেস্টিং এর জন্য সকল অরিজিনকে (যেমন API টেস্টার) অনুমতি দেওয়া হলো
// এটি আপনার "Failed to fetch" সমস্যার সমাধান করবে।
app.use(cors());
// ------------------

// bodyParser-এর পরিবর্তে express-এর বিল্ট-ইন মেথড
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public')); // socket.io ক্লায়েন্টের জন্য?

// --- ফাইল আপলোড (Multer) ---
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- MongoDB কানেকশন ---
const uri = process.env.MONGODB_URI; // .env ফাইল থেকে URI লোড করা
if (!uri) {
  throw new Error('MONGODB_URI is not defined in .env file');
}
const client = new MongoClient(uri);

// --- IoT ডেটার জন্য ব্যাচ ইনসার্ট (Batch Insert) সেটআপ ---
let espDataBuffer = []; // ESP32 থেকে আসা ডেটা এখানে জমা হবে
const BATCH_INTERVAL_MS = 10000; // ১০ সেকেন্ড পর পর ডাটাবেসে সেভ হবে

/**
 * এই ফাংশনটি বাফারে জমা হওয়া সব ডেটা একসাথে ডাটাবেসে ইনসার্ট করে
 */
async function flushDataBuffer(collection) {
  if (espDataBuffer.length === 0) {
    return; // বাফার খালি থাকলে কিছু করার নেই
  }

  // বাফারের একটি কপি তৈরি করি এবং মূল বাফারটি খালি করি
  const dataToInsert = [...espDataBuffer];
  espDataBuffer = [];

  console.log(`[Batch Insert] Inserting ${dataToInsert.length} documents...`);

  try {
    // ordered: false মানে হলো, কোনো একটি ডেটাতে সমস্যা থাকলেও বাকিগুলো ইনসার্ট হবে
    await collection.insertMany(dataToInsert, { ordered: false });
    console.log(`[Batch Insert] Successfully inserted ${dataToInsert.length} documents.`);
  } catch (error) {
    console.error("[Batch Insert] Failed to insert data:", error.message);
    // এখানে ফেইল হওয়া ডেটাগুলো লগিং বা অন্য ফাইলে সেভ করার ব্যবস্থা করতে পারেন
  }
}
// --- ব্যাচ ইনসার্ট সেটআপ শেষ ---

async function run() {
  try {
    await client.connect();
    console.log('DB connected');

    const db = client.db('Esp32data');

    // --- কালেকশন ডিফাইন করা ---
    // !! জরুরি: সেরা পারফরম্যান্সের জন্য esp_timeseries_data নামে একটি Time Series কালেকশন তৈরি করুন
    // এটি সাধারণ কালেকশনের চেয়ে অনেক দ্রুত এবং কম জায়গা নেবে।
    //const EspCollection = db.collection('esp_timeseries_data4'); // অথবা আপনার পুরানো 'espdata2'
    const EspCollection = db.collection('espdata2'); // অথবা আপনার পুরানো 'espdata2'
    
  const wholesaleCollection = db.collection('wholesale');
  const lotary = db.collection('lotary');
  // devices collection to track lastSeen/status
  const devicesCollection = db.collection('devices');
  // users collection for authentication and device ownership
  const usersCollection = db.collection('users');

    // --- ব্যাচ ইনসার্ট টাইমার চালু করা ---
    // প্রতি ১০ সেকেন্ড পর পর বাফার খালি করার ফাংশনটি কল করা হবে
    setInterval(() => flushDataBuffer(EspCollection), BATCH_INTERVAL_MS);

    // --- রুট (Routes) ---

    // ESP32 থেকে ডেটা পড়া (GET)
    app.get('/api/esp32', async (req, res) => {
      const query = {};
      const cursor = EspCollection.find(query);
      const Data = await cursor.toArray();
      res.send(Data);
    });

    // !! ক্রিটিক্যাল: ESP32 থেকে ডেটা গ্রহণ (POST) - ব্যাচ মোডে
    // এই রুটটি এখন আর ডাটাবেসে সরাসরি রাইট করবে না, বাফারে জমা করবে
    app.post('/api/esp32pp', async (req, res) => {
      try {
        const data = req.body;

        // ফিক্স: স্ট্রিং Timestamp-কে Date অবজেক্টে রূপান্তর করা
        data.timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
        data.receivedAt = new Date(); // সার্ভার রিসিভ টাইম

        // ডেটাটিকে বাফারে Push করা
        espDataBuffer.push(data);

        // ক্লায়েন্টকে (ESP32) দ্রুত রেসপন্স পাঠানো (202 Accepted)
        res.status(200).send({ message: 'Data accepted and queued.' });
      } catch (error) {
        res.status(400).send({ message: 'Invalid data format' });
      }
    });



app.post('/api/esp32p', async (req, res) => {
  try {
    const data = req.body;

    // Bangladesh (UTC+6) সময় গণনা
    const now = new Date();
    const utc = now.getTime() + now.getTimezoneOffset() * 60000;
    const bdTime = new Date(utc + 6 * 60 * 60000);

    // যদি ESP32 থেকে timestamp আসে, সেটাকেও BD টাইমে রূপান্তর করা
    if (data.timestamp) {
      const t = new Date(data.timestamp);
      const utcT = t.getTime() + t.getTimezoneOffset() * 60000;
      data.timestamp = new Date(utcT + 6 * 60 * 60000);
    } else {
      data.timestamp = bdTime;
    }

    // সার্ভার রিসিভ টাইম (Bangladesh Time)
    data.receivedAt = bdTime;

    // ডেটা বাফারে যোগ করা
    espDataBuffer.push(data);

    // দ্রুত রেসপন্স পাঠানো
    res.status(200).send({ message: 'Data accepted and queued.' });
  } catch (error) {
    res.status(400).send({ message: 'Invalid data format' });
  }
});

    // GET /api/device/data
    // Returns the last N (default 300) data points from EspCollection, optional ?uid=...
    app.get('/api/device/data', async (req, res) => {
      try {
        const { uid, limit } = req.query || {};
        const lim = Math.min(1000, Math.max(1, parseInt(limit, 10) || 600)); // cap between 1 and 1000
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

    // GET /api/backup
    // Creates a JSON dump of EspCollection (optionally filtered by uid) and returns a ZIP for download
    app.get('/api/backup', async (req, res) => {
      try {
        const { uid } = req.query || {};
        const q = {};
        if (uid) q.uid = String(uid);

        // create temp directory for this backup
        const tmpDir = path.join(os.tmpdir(), `esp-backup-${Date.now()}`);
        fs.mkdirSync(tmpDir, { recursive: true });

        const jsonPath = path.join(tmpDir, 'espdata.json');

        // stream collection to JSON array to avoid large memory usage
        const out = fs.createWriteStream(jsonPath, { encoding: 'utf8' });
        out.write('[');
        let first = true;

        const cursor = EspCollection.find(q).sort({ timestamp: 1 });
        for await (const doc of cursor) {
          // convert ObjectId and Date to serializable values
          const copy = { ...doc };
          if (copy._id && copy._id.toString) copy._id = copy._id.toString();
          if (copy.timestamp && copy.timestamp.toISOString) copy.timestamp = copy.timestamp.toISOString();
          if (!first) out.write(',\n');
          out.write(JSON.stringify(copy));
          first = false;
        }

        out.write(']');
        out.end();

        await new Promise((resolve, reject) => {
          out.on('finish', resolve);
          out.on('error', reject);
        });

        // create zip
        const zipPath = path.join(tmpDir, 'espdata.zip');
        const output = fs.createWriteStream(zipPath);
        const archive = archiver('zip', { zlib: { level: 9 } });

        archive.pipe(output);
        archive.file(jsonPath, { name: 'espdata.json' });
        await archive.finalize();

        await new Promise((resolve, reject) => {
          output.on('close', resolve);
          output.on('error', reject);
        });

        // send file as attachment
        res.download(zipPath, 'espdata.zip', (err) => {
          // cleanup temp directory (best-effort)
          try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
          } catch (e) {
            console.warn('Failed to cleanup tmpDir:', tmpDir, e && e.message);
          }
          if (err) {
            console.error('Error sending backup zip:', err);
          }
        });
      } catch (error) {
        console.error('Error in /api/backup:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // New backup job system: start job, stream progress via SSE, download when ready
    const backupJobs = new Map(); // jobId -> { status, progress, tmpDir, zipPath, error }

    // POST /api/backup/start
    // Body: { uid?: string }
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
              if (copy._id && copy._id.toString) copy._id = copy._id.toString();
              if (copy.timestamp && copy.timestamp.toISOString) copy.timestamp = copy.timestamp.toISOString();
              if (!first) out.write(',\n');
              out.write(JSON.stringify(copy));
              first = false;
              written++;

              // update progress every 1% or every 500 docs
              if (total > 0) {
                const pct = Math.floor((written / total) * 100);
                if (pct !== job.progress && (written % 500 === 0 || pct % 1 === 0)) {
                  job.progress = pct;
                }
              } else {
                // unknown total, use heuristic
                if (written % 500 === 0) job.progress = Math.min(99, job.progress + 1);
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

      // set headers for SSE
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');
      res.flushHeaders && res.flushHeaders();

      // send initial state
      res.write(`event: progress\ndata: ${JSON.stringify({ status: job.status, progress: job.progress })}\n\n`);

      const iv = setInterval(() => {
        const j = backupJobs.get(jobId);
        if (!j) {
          res.write(`event: error\ndata: ${JSON.stringify({ message: 'Job removed' })}\n\n`);
          clearInterval(iv);
          return res.end();
        }

        res.write(`event: progress\ndata: ${JSON.stringify({ status: j.status, progress: j.progress, error: j.error || null })}\n\n`);

        if (j.status === 'done' || j.status === 'error') {
          // notify final and close
          res.write(`event: done\ndata: ${JSON.stringify({ status: j.status, progress: j.progress, download: j.status === 'done' ? `/api/backup/download/${jobId}` : null, error: j.error || null })}\n\n`);
          clearInterval(iv);
          return res.end();
        }
      }, 1000);

      // cleanup when client disconnects
      req.on('close', () => {
        clearInterval(iv);
      });
    });

    // GET /api/backup/download/:jobId
    app.get('/api/backup/download/:jobId', (req, res) => {
      const { jobId } = req.params;
      const job = backupJobs.get(jobId);
      if (!job) return res.status(404).send({ success: false, message: 'Job not found' });
      if (job.status !== 'done' || !job.zipPath) return res.status(400).send({ success: false, message: 'Job not ready' });

      res.download(job.zipPath, 'espdata.zip', (err) => {
        // optionally cleanup after download
        try {
          fs.rmSync(job.tmpDir, { recursive: true, force: true });
        } catch (e) {
          console.warn('Failed to cleanup backup tmpDir after download:', e && e.message);
        }
        backupJobs.delete(jobId);
        if (err) console.error('Error sending backup download:', err);
      });
    });

    // POST /api/device/data-by-range
    // Body: { uid, start: 'YYYY-MM-DD HH:mm:ss', end: 'YYYY-MM-DD HH:mm:ss', limit }
    app.post('/api/device/data-by-range', async (req, res) => {
      try {
        const { uid, start, end, limit } = req.body || {};
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        // Helper to parse date strings like '2025-10-27 00:00:00' or ISO strings
        function parseDate(s, fallback) {
          if (!s) return fallback;
          // convert space between date and time to 'T' for ISO parsing
          const normalized = String(s).trim().replace(' ', 'T');
          const d = new Date(normalized);
          if (isNaN(d.getTime())) return null;
          return d;
        }

        const startDate = parseDate(start, new Date(0));
        const endDateRaw = parseDate(end, new Date());
        if (!startDate || !endDateRaw) return res.status(400).send({ success: false, message: 'Invalid start or end date' });

        // If end provided without time it will be treated as start of that day; to be safe we keep the provided time.
        const endDate = new Date(endDateRaw);

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

    // অন্যান্য রাউট (এগুলো কম ট্রাফিকের, তাই insertOne ঠিক আছে)
    app.get('/api/accounts/:id', async (req, res) => {
      try {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) }; // ফিক্স: new ObjectId
        const booking = await EspCollection.findOne(query);
        res.send(booking);
      } catch (e) {
        res.status(400).send({ message: 'Invalid ID format' });
      }
    });

    app.get('/api/accounts', async (req, res) => {
      const query = {};
      const cursor = EspCollection.find(query);
      const accounts = await cursor.toArray();
      res.send(accounts);
    });

    app.get('/api/wholesale', async (req, res) => {
      const query = {};
      const cursor = wholesaleCollection.find(query);
      const accounts = await cursor.toArray();
      res.send(accounts);
    });

    app.get('/api/lotary', async (req, res) => {
      const query = {};
      const cursor = lotary.find(query);
      const Lotary = await cursor.toArray();
      res.send(Lotary);
    });

    app.post('/api/lotary', async (req, res) => {
      const nextcort = req.body;
      const result = await lotary.insertOne(nextcort);
      res.send(result);
    });

    // ফিক্স: তারিখ ভিত্তিক রিপোর্ট (ডাটাবেস কোয়েরি)
    // এই কোয়েরিটি এখন 'timestamp' ফিল্ডের ওপর ভিত্তি করে করা হয়েছে
    app.get('/api/accountsreportbydate', async (req, res) => {
      try {
        const { sdate, edate } = req.query;
        
        const startDate = new Date(sdate);
        const endDate = new Date(edate);
        endDate.setHours(23, 59, 59, 999); // দিনের শেষ পর্যন্ত

        // ফিক্স: 'Hisab_Date'-এর পরিবর্তে 'timestamp' (Date অবজেক্ট) দিয়ে কোয়েরি
        const query = {
          timestamp: {
            $gte: startDate,
            $lte: endDate
          }
        };
        
        const filterdate = await EspCollection.find(query).toArray();
        res.send(filterdate);
      } catch (error) {
        console.error("Error in date report:", error);
        res.status(500).send({ message: 'Error fetching report' });
      }
    });

    // GET /api/device/status - summary of devices
    app.get('/api/device/status', async (req, res) => {
      try {
        const total = await devicesCollection.countDocuments();
        const online = await devicesCollection.countDocuments({ status: 'online' });
        const offline = total - online;
        return res.send({ total, online, offline });
      } catch (error) {
        console.error('Error in /api/device/status:', error);
        return res.status(500).send({ message: 'Internal server error' });
      }
    });

    // --- Admin routes (protected) ---
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

    // GET /api/admin/devices
    // Returns list of devices with owner info (if any)
    app.get('/api/admin/devices', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check || check.ok !== true) return; // ensureAdmin already sent response

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
          { $project: { _id: 0, uid: 1, status: 1, lastSeen: 1, owners: 1 } }
        ]).toArray();

        return res.send(devices);
      } catch (error) {
        console.error('Error in /api/admin/devices:', error);
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // GET /api/admin/report?period=monthly|daily|yearly&year=2025
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
              avgTemp: { $avg: '$temperature' },
              avgRain: { $avg: '$rainfall' },
              count: { $sum: 1 }
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
              avgTemp: { $avg: '$temperature' },
              avgRain: { $avg: '$rainfall' },
              count: { $sum: 1 }
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
            avgTemp: { $avg: '$temperature' },
            avgRain: { $avg: '$rainfall' },
            count: { $sum: 1 }
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

      // POST /api/user/register
      // Body: { name, email, password }
      app.post('/api/user/register', async (req, res) => {
        try {
          const { name, email, password } = req.body || {};
          if (!name || !email || !password) {
            return res.status(400).send({ success: false, message: 'name, email and password are required' });
          }

          const normalizedEmail = String(email).trim().toLowerCase();

          // check existing
          const existing = await usersCollection.findOne({ email: normalizedEmail });
          if (existing) {
            return res.status(400).send({ success: false, message: 'Email already registered' });
          }

          // hash password
          const passwordHash = await bcrypt.hash(String(password), 10);

          const newUser = {
            name: String(name).trim(),
            email: normalizedEmail,
            passwordHash,
            devices: [],
            createdAt: new Date()
          };

          await usersCollection.insertOne(newUser);
          return res.send({ success: true, message: 'User registered successfully' });
        } catch (error) {
          console.error('Error in /api/user/register:', error);
          return res.status(500).send({ success: false, message: 'Internal server error' });
        }
      });

        // POST /api/user/login
        // Body: { email, password }
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

        // POST /api/user/device/add (protected)
        // Body: { uid }
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
        // Body: { uid }
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

        // GET /api/user/device/:uid/data (protected)
        // Query: ?start=YYYY-MM-DD&end=YYYY-MM-DD
        app.get('/api/user/device/:uid/data', authenticateJWT, async (req, res) => {
          try {
            const userId = req.user && req.user.userId;
            const uid = req.params.uid;
            if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });

            const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
            if (!user) return res.status(404).send({ success: false, message: 'User not found' });

            // Ensure the device belongs to the user
            if (!user.devices || !user.devices.includes(uid)) {
              return res.status(403).send({ success: false, message: 'Forbidden: device not assigned to user' });
            }

            const { start, end } = req.query || {};
            const startDate = start ? new Date(start) : new Date(0);
            const endDate = end ? new Date(end) : new Date();
            // if end provided without time, set to end of day
            endDate.setHours(23, 59, 59, 999);

            const query = { uid, timestamp: { $gte: startDate, $lte: endDate } };
            const docs = await EspCollection.find(query)
              .project({ temperature: 1, water_level: 1, rainfall: 1, timestamp: 1, _id: 0 })
              .toArray();

            return res.send(docs);
          } catch (error) {
            console.error('Error in /api/user/device/:uid/data:', error);
            return res.status(500).send({ success: false, message: 'Internal server error' });
          }
        });

        // GET /api/user/devices (protected)
        // Returns user's devices with status and lastSeen
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
              return { uid, status: d ? d.status || 'offline' : 'offline', lastSeen: d ? d.lastSeen : null };
            });

            return res.send(result);
          } catch (error) {
            console.error('Error in /api/user/devices:', error);
            return res.status(500).send({ success: false, message: 'Internal server error' });
          }
        });

  } finally {
    // প্রোডাকশন সার্ভারে ক্লায়েন্ট বন্ধ করা উচিত নয়
    // await client.close();
  }
}
run().catch(console.dir);

// Socket.io কানেকশন (যদি প্রয়োজন হয়)
io.on('connection', (socket) => {
  console.log('A user connected via socket.io');
  socket.on('disconnect', () => {
    console.log('User disconnected');
  });
});

// রুট পেইজ
app.get("/", (req, res) => {
  res.send(`<h1 style="text-align: center; color: green;">Max it Server (Production Ready) is Running at ${port}</h1>`);
});

// ক্রিটিক্যাল ফিক্স: socket.io এর জন্য http_server.listen() ব্যবহার করতে হবে
http_server.listen(port, () => {
  console.log(`Max it Production server running at: ${port}`);
});

