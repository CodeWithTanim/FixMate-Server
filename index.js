import 'dotenv/config';
import express from 'express';
import { MongoClient } from 'mongodb';

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || '';
const MONGODB_DBNAME = process.env.MONGODB_DBNAME || 'fixmate-db';

// MongoDB connection reuse with cached client & promise
let cachedClient = null;
let cachedDb = null;
let connectionPromise = null;

export async function connectToDatabase() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  if (!MONGODB_URI) {
    throw new Error('MONGODB_URI is not configured');
  }

  if (!connectionPromise) {
    const client = new MongoClient(MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
    });

    connectionPromise = client
      .connect()
      .then((connectedClient) => {
        cachedClient = connectedClient;
        cachedDb = connectedClient.db(MONGODB_DBNAME);
        return { client: cachedClient, db: cachedDb };
      })
      .catch((err) => {
        connectionPromise = null;
        cachedClient = null;
        cachedDb = null;
        throw err;
      });
  }

  return connectionPromise;
}

export async function getDb() {
  const { db } = await connectToDatabase();
  return db;
}

export async function pingDatabase() {
  const db = await getDb();
  await db.command({ ping: 1 });
  return true;
}

// Root route
app.get('/', (req, res) => {
  res.status(200).json({
    name: 'FixMate API',
    version: '1.0.0',
    status: 'running',
  });
});

// Liveness check - independent of database
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// Readiness check - bounded database ping
app.get('/health/ready', async (req, res) => {
  try {
    await pingDatabase();
    res.status(200).json({
      status: 'ready',
      database: 'connected',
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(503).json({
      status: 'unavailable',
      error: 'Database connection failed',
      timestamp: new Date().toISOString(),
    });
  }
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`FixMate server running on port ${PORT}`);
  });
}

export default app;
