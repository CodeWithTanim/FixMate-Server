import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || '';
const MONGODB_DBNAME = process.env.MONGODB_DBNAME || 'fixmate-db';
const CORS_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map((o) => o.trim()).filter(Boolean)
  : ['http://localhost:3000'];
const JWT_SECRET = process.env.JWT_SECRET || '';
const JWT_ISSUER = process.env.JWT_ISSUER || 'http://localhost:3000';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'fixmate-api';

// Exact origin CORS configuration
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) {
      return callback(null, true);
    }

    if (CORS_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    const corsError = new Error(`Origin ${origin} not allowed by CORS`);
    corsError.statusCode = 403;
    corsError.name = 'Forbidden';
    return callback(corsError);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '100kb' }));

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

// Authentication middleware
export async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Missing or malformed Authorization header',
    });
  }

  const token = authHeader.split(' ')[1];
  let decoded;

  try {
    decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Token has expired',
      });
    }

    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid token signature or payload',
    });
  }

  const sub = decoded.sub;
  if (!sub) {
    return res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid token subject',
    });
  }

  try {
    const db = await getDb();
    const usersCollection = db.collection('user');

    const query = [{ id: sub }, { _id: sub }];
    if (ObjectId.isValid(sub)) {
      query.push({ _id: new ObjectId(sub) });
    }

    const user = await usersCollection.findOne({ $or: query });

    if (!user) {
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'User account not found',
      });
    }

    req.user = {
      id: user.id || user._id?.toString(),
      name: user.name,
      email: user.email,
      image: user.image || null,
      role: user.role || 'customer',
      phone: user.phone || null,
      area: user.area || null,
      bio: user.bio || null,
      createdAt: user.createdAt,
    };

    next();
  } catch (dbErr) {
    console.error('Database error in verifyToken:', dbErr.message);
    return res.status(503).json({
      error: 'Service Unavailable',
      message: 'Database temporarily unavailable',
    });
  }
}

export function verifyCustomer(req, res, next) {
  if (req.user?.role !== 'customer') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Customer access required',
    });
  }
  next();
}

export function verifyTechnician(req, res, next) {
  if (req.user?.role !== 'technician') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Technician access required',
    });
  }
  next();
}

export function verifyAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }
  next();
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

// Authenticated current user profile projection
app.get('/api/me', verifyToken, (req, res) => {
  res.status(200).json({
    user: req.user,
  });
});

// GET /api/services - Read approved and available services with search, filters, sorting, and pagination
app.get('/api/services', async (req, res, next) => {
  try {
    const db = await getDb();
    const servicesCollection = db.collection('services');

    const query = {
      approvalStatus: 'approved',
      isAvailable: true,
    };

    // Free-text search across title, description, and category (with regex escaping)
    if (req.query.search && typeof req.query.search === 'string') {
      const escaped = req.query.search.trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      if (escaped) {
        query.$or = [
          { title: { $regex: escaped, $options: 'i' } },
          { description: { $regex: escaped, $options: 'i' } },
          { category: { $regex: escaped, $options: 'i' } },
        ];
      }
    }

    // Category filter
    if (req.query.category && typeof req.query.category === 'string') {
      const cat = req.query.category.trim();
      if (cat && cat.toLowerCase() !== 'all') {
        query.category = { $regex: `^${cat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' };
      }
    }

    // Service mode filter: Home Visit or Shop Drop-off
    if (req.query.serviceMode && typeof req.query.serviceMode === 'string') {
      const mode = req.query.serviceMode.trim();
      if (mode && mode.toLowerCase() !== 'all') {
        query.serviceMode = { $regex: `^${mode.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' };
      }
    }

    // Sorting
    const sortParam = req.query.sort || 'newest';
    let sortQuery = { createdAt: -1, _id: -1 };
    if (sortParam === 'price_asc') {
      sortQuery = { basePrice: 1, _id: -1 };
    } else if (sortParam === 'price_desc') {
      sortQuery = { basePrice: -1, _id: -1 };
    }

    // Bounded pagination
    const rawLimit = parseInt(req.query.limit, 10);
    const limit = Number.isInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, 50) : 9;

    const rawPage = parseInt(req.query.page, 10);
    const page = Number.isInteger(rawPage) && rawPage > 0 ? rawPage : 1;
    const skip = (page - 1) * limit;

    const [services, total] = await Promise.all([
      servicesCollection
        .find(query)
        .sort(sortQuery)
        .skip(skip)
        .limit(limit)
        .toArray(),
      servicesCollection.countDocuments(query),
    ]);

    const formattedServices = services.map((s) => ({
      id: s._id.toString(),
      _id: s._id.toString(),
      title: s.title,
      category: s.category,
      description: s.description,
      image: s.image,
      basePrice: s.basePrice,
      estimatedDuration: s.estimatedDuration,
      serviceMode: s.serviceMode,
      serviceArea: s.serviceArea,
      technicianName: s.technicianName,
      technicianEmail: s.technicianEmail,
      approvalStatus: s.approvalStatus,
      isAvailable: s.isAvailable,
      createdAt: s.createdAt instanceof Date ? s.createdAt.toISOString() : s.createdAt,
    }));

    res.status(200).json({
      data: formattedServices,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit) || 1,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/services/:id - Read single approved service
app.get('/api/services/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Invalid service ID format',
      });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');

    const service = await servicesCollection.findOne({
      _id: new ObjectId(id),
      approvalStatus: 'approved',
      isAvailable: true,
    });

    if (!service) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'Service not found or unavailable',
      });
    }

    res.status(200).json({
      service: {
        ...service,
        id: service._id.toString(),
        _id: service._id.toString(),
        createdAt:
          service.createdAt instanceof Date ? service.createdAt.toISOString() : service.createdAt,
      },
    });
  } catch (err) {
    next(err);
  }
});

// 404 handler
app.use((req, res, next) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
  });
});

// Centralized error handler
app.use((err, req, res, next) => {
  const statusCode = err.status || err.statusCode || (err.name === 'UnauthorizedError' ? 401 : 500);
  res.status(statusCode).json({
    error: err.name || 'Error',
    message: statusCode === 500 ? 'Internal server error' : err.message,
  });
});

if (!process.env.VERCEL && process.env.NODE_ENV !== 'test') {
  app.listen(PORT, () => {
    console.log(`FixMate server running on port ${PORT}`);
  });
}

export default app;
