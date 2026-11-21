import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId } from 'mongodb';
import jwt from 'jsonwebtoken';
import Stripe from 'stripe';

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

const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

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
  allowedHeaders: ['Content-Type', 'Authorization', 'stripe-signature'],
};

app.use(cors(corsOptions));

// Shared Stripe payment fulfillment helper (idempotent for webhook & client return)
export async function fulfillPaymentSession(session) {
  if (!session) return null;

  const db = await getDb();
  const bookingsCollection = db.collection('bookings');
  const paymentsCollection = db.collection('payments');

  // 1. Verify session completion and currency invariants
  if (session.payment_status !== 'paid') {
    console.error('Ignoring payment fulfillment for unpaid session:', session.id);
    return null;
  }
  if (session.currency && session.currency.toLowerCase() !== 'usd') {
    console.error('Invalid currency in session:', session.currency);
    return null;
  }
  if (session.mode && session.mode !== 'payment') {
    console.error('Invalid session mode for repair payment:', session.mode);
    return null;
  }

  // 2. Validate booking ID
  const bookingId = session.metadata?.bookingId || session.client_reference_id;
  if (!bookingId || !ObjectId.isValid(bookingId)) {
    console.error('Invalid booking ID in session metadata:', bookingId);
    return null;
  }

  // 3. Retrieve booking and enforce state machine invariant
  const booking = await bookingsCollection.findOne({ _id: new ObjectId(bookingId) });
  if (!booking) {
    console.error('Booking not found for payment fulfillment:', bookingId);
    return null;
  }

  // Critical invariant: Only completed repair jobs can be fulfilled/paid!
  if (booking.status !== 'completed') {
    console.error(`Cannot fulfill payment: booking ${bookingId} is in status '${booking.status}', not 'completed'`);
    return null;
  }

  // 4. Verify customer ownership
  if (
    session.customer_email &&
    booking.customerEmail &&
    session.customer_email.toLowerCase() !== booking.customerEmail.toLowerCase()
  ) {
    console.error('Customer email mismatch between Stripe session and booking');
    return null;
  }

  if (
    session.metadata?.customerId &&
    booking.customerId &&
    session.metadata.customerId !== booking.customerId
  ) {
    console.error('Customer ID mismatch between Stripe session and booking');
    return null;
  }

  // 5. Verify exact expected cents vs received cents
  const expectedAmount = booking.finalAmount || booking.basePrice;
  if (typeof expectedAmount !== 'number' || expectedAmount <= 0) {
    console.error('Invalid expected amount on booking:', expectedAmount);
    return null;
  }
  const expectedCents = Math.round(expectedAmount * 100);
  const paidCents = Math.round(session.amount_total || 0);
  if (paidCents !== expectedCents) {
    console.error(
      `Payment amount mismatch for booking ${bookingId}. Expected: ${expectedCents} cents ($${expectedAmount}), received: ${paidCents} cents`
    );
    return null;
  }

  // 6. If booking is already paid, return idempotent success
  if (booking.paymentStatus === 'paid') {
    return booking;
  }

  // Check if payment ledger record already exists (e.g. from prior webhook or interrupted write)
  const existingBookingPayment = await paymentsCollection.findOne({ bookingId: booking._id.toString() });
  if (existingBookingPayment) {
    // Reconcile booking from existing authoritative payment ledger record
    if (existingBookingPayment.status === 'succeeded') {
      const settledAmount = typeof existingBookingPayment.amount === 'number'
        ? existingBookingPayment.amount
        : paidCents / 100;

      await bookingsCollection.updateOne(
        { _id: new ObjectId(bookingId), paymentStatus: { $ne: 'paid' } },
        {
          $set: {
            paymentStatus: 'paid',
            stripePaymentIntentId: existingBookingPayment.stripePaymentIntentId || session.payment_intent || null,
            stripeSessionId: existingBookingPayment.stripeSessionId || session.id,
            paidAt: existingBookingPayment.createdAt || new Date(),
            updatedAt: new Date(),
          },
          $push: {
            statusHistory: {
              status: 'paid',
              timestamp: existingBookingPayment.createdAt || new Date(),
              changedBy: booking.customerEmail,
              role: 'customer',
              note: `Payment of $${Number(settledAmount).toFixed(2)} completed successfully via Stripe`,
            },
          },
        }
      );

      return await bookingsCollection.findOne({ _id: new ObjectId(bookingId) });
    }
  }

  // 7. Enforce exactly-once payment ledger insertion (unique on bookingId)
  const paidAmount = (paidCents / 100).toFixed(2);
  let authoritativePayment = null;

  try {
    await paymentsCollection.insertOne({
      stripeSessionId: session.id,
      stripePaymentIntentId: session.payment_intent || null,
      bookingId: booking._id.toString(),
      serviceId: booking.serviceId,
      serviceTitle: booking.serviceTitle,
      customerEmail: booking.customerEmail,
      customerName: booking.customerName,
      technicianEmail: booking.technicianEmail,
      technicianName: booking.technicianName,
      amount: paidCents / 100,
      currency: 'usd',
      status: 'succeeded',
      createdAt: new Date(),
    });
    authoritativePayment = {
      stripeSessionId: session.id,
      stripePaymentIntentId: session.payment_intent || null,
      amount: paidCents / 100,
      createdAt: new Date(),
    };
  } catch (err) {
    if (err.code === 11000 || err.message?.includes('duplicate key')) {
      // In case of race condition or duplicate key, load authoritative existing payment
      authoritativePayment = await paymentsCollection.findOne({ bookingId: booking._id.toString() });
    } else {
      throw err;
    }
  }

  const finalPayment = authoritativePayment || {
    stripeSessionId: session.id,
    stripePaymentIntentId: session.payment_intent || null,
    amount: paidCents / 100,
    createdAt: new Date(),
  };

  // 8. Atomic exactly-once update on booking record (reconciliation safe)
  await bookingsCollection.updateOne(
    { _id: new ObjectId(bookingId), paymentStatus: { $ne: 'paid' } },
    {
      $set: {
        paymentStatus: 'paid',
        stripePaymentIntentId: finalPayment.stripePaymentIntentId || null,
        stripeSessionId: finalPayment.stripeSessionId || null,
        paidAt: finalPayment.createdAt || new Date(),
        updatedAt: new Date(),
      },
      $push: {
        statusHistory: {
          status: 'paid',
          timestamp: finalPayment.createdAt || new Date(),
          changedBy: booking.customerEmail,
          role: 'customer',
          note: `Payment of $${Number(finalPayment.amount).toFixed(2)} completed successfully via Stripe`,
        },
      },
    }
  );

  return await bookingsCollection.findOne({ _id: new ObjectId(bookingId) });
}

// Stripe webhook route mounted before JSON body parser to preserve raw buffer
app.post(
  '/api/payments/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    if (!stripe || !STRIPE_WEBHOOK_SECRET) {
      return res.status(503).json({
        error: 'Service Unavailable',
        message: 'Stripe webhook handler is not configured with STRIPE_WEBHOOK_SECRET',
      });
    }

    try {
      event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      console.error('Stripe webhook signature error:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        await fulfillPaymentSession(session);
      }
      res.status(200).json({ received: true });
    } catch (err) {
      console.error('Error handling webhook event:', err);
      res.status(500).json({ error: 'Fulfillment failed' });
    }
  }
);

// Standard JSON body parser for all other routes
app.use(express.json({ limit: '10mb' }));

// MongoDB connection reuse with cached client & promise
let cachedClient = null;
let cachedDb = null;
let connectionPromise = null;
let indexesInitialized = false;

export async function ensureDatabaseIndexes(db) {
  if (indexesInitialized) return;
  try {
    await Promise.all([
      db.collection('services').createIndex({ approvalStatus: 1, isAvailable: 1, createdAt: -1 }),
      db.collection('services').createIndex({ technicianEmail: 1, createdAt: -1 }),
      db.collection('bookings').createIndex({ customerEmail: 1, createdAt: -1 }),
      db.collection('bookings').createIndex({ technicianEmail: 1, status: 1 }),
      db.collection('bookings').createIndex(
        { customerEmail: 1, serviceId: 1 },
        {
          unique: true,
          partialFilterExpression: {
            status: { $in: ['requested', 'accepted', 'in-progress'] },
          },
          name: 'unique_active_customer_service_booking',
        }
      ),
      db.collection('payments').createIndex({ stripeSessionId: 1 }, { unique: true, sparse: true }),
      db.collection('payments').createIndex(
        { bookingId: 1 },
        { unique: true, name: 'unique_booking_payment' }
      ),
      db.collection('payments').createIndex({ customerEmail: 1, createdAt: -1 }),
      db.collection('user').createIndex({ email: 1 }, { unique: true, sparse: true }),
    ]);
    indexesInitialized = true;
  } catch (err) {
    console.warn('Index initialization notice:', err.message);
  }
}

export function setTestDb(db, client = null) {
  cachedDb = db;
  cachedClient = client;
}

export async function connectToDatabase() {
  if (cachedDb) {
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
      .then(async (connectedClient) => {
        cachedClient = connectedClient;
        cachedDb = connectedClient.db(MONGODB_DBNAME);
        await ensureDatabaseIndexes(cachedDb);
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
      serviceArea: user.serviceArea || user.area || null,
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

// Readiness check - bounded database ping with latency measurement
app.get('/health/ready', async (req, res) => {
  const startTime = Date.now();
  try {
    await pingDatabase();
    const latencyMs = Date.now() - startTime;
    const memory = process.memoryUsage();
    res.status(200).json({
      status: 'ready',
      database: 'connected',
      latencyMs,
      memory: {
        heapUsedMb: Math.round((memory.heapUsed / 1024 / 1024) * 100) / 100,
        rssMb: Math.round((memory.rss / 1024 / 1024) * 100) / 100,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res.status(503).json({
      status: 'unavailable',
      error: 'Database connection failed',
      latencyMs: Date.now() - startTime,
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

    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 6));
    const skip = (page - 1) * limit;

    const query = {
      approvalStatus: 'approved',
      isAvailable: true,
    };

    if (req.query.search && typeof req.query.search === 'string') {
      const trimmedSearch = req.query.search.trim();
      if (trimmedSearch) {
        const escapedSearch = trimmedSearch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        query.$or = [
          { title: { $regex: escapedSearch, $options: 'i' } },
          { description: { $regex: escapedSearch, $options: 'i' } },
          { serviceArea: { $regex: escapedSearch, $options: 'i' } },
        ];
      }
    }

    if (req.query.category && typeof req.query.category === 'string' && req.query.category !== 'all') {
      query.category = req.query.category;
    }

    if (req.query.serviceMode && typeof req.query.serviceMode === 'string' && req.query.serviceMode !== 'all') {
      query.serviceMode = req.query.serviceMode;
    }

    let sort = { createdAt: -1, _id: -1 };
    const sortParam = req.query.sort;
    if (sortParam === 'price_asc') {
      sort = { basePrice: 1, _id: -1 };
    } else if (sortParam === 'price_desc') {
      sort = { basePrice: -1, _id: -1 };
    } else if (sortParam === 'newest') {
      sort = { createdAt: -1, _id: -1 };
    }

    const totalCount = await servicesCollection.countDocuments(query);
    const services = await servicesCollection
      .find(query)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .toArray();

    const formattedServices = services.map((s) => ({
      ...s,
      id: s._id.toString(),
      _id: s._id.toString(),
      createdAt: s.createdAt instanceof Date ? s.createdAt.toISOString() : s.createdAt,
    }));

    res.status(200).json({
      data: formattedServices,
      pagination: {
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit) || 1,
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/services/:id - Read single service details (must be approved & available)
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
        message: 'Service listing not found or is currently unavailable',
      });
    }

    res.status(200).json({
      service: {
        id: service._id.toString(),
        _id: service._id.toString(),
        title: service.title,
        category: service.category,
        description: service.description,
        image: service.image,
        basePrice: service.basePrice,
        estimatedDuration: service.estimatedDuration,
        serviceMode: service.serviceMode,
        serviceArea: service.serviceArea,
        technicianId: service.technicianId,
        technicianName: service.technicianName,
        technicianEmail: service.technicianEmail,
        approvalStatus: service.approvalStatus,
        isAvailable: service.isAvailable,
        createdAt:
          service.createdAt instanceof Date ? service.createdAt.toISOString() : service.createdAt,
      },
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/services - Technician create service (defaults to pending & available)
app.post('/api/services', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const { title, category, description, image, basePrice, estimatedDuration, serviceMode, serviceArea } = req.body;

    const allowedCategories = ['Smartphone', 'Laptop & PC', 'AC', 'Refrigerator', 'TV', 'Washing Machine', 'Electrical'];
    if (!category || !allowedCategories.includes(category)) {
      return res.status(400).json({ error: 'Validation Error', message: `Invalid category. Allowed: ${allowedCategories.join(', ')}` });
    }

    const allowedModes = ['Home Visit', 'Shop Drop-off'];
    if (!serviceMode || !allowedModes.includes(serviceMode)) {
      return res.status(400).json({ error: 'Validation Error', message: `Invalid service mode. Allowed: ${allowedModes.join(', ')}` });
    }

    const numericPrice = parseFloat(basePrice);
    if (isNaN(numericPrice) || numericPrice <= 0) {
      return res.status(400).json({ error: 'Validation Error', message: 'Base price must be a positive number' });
    }

    if (!title || !description || !estimatedDuration || !serviceArea) {
      return res.status(400).json({ error: 'Validation Error', message: 'Title, description, estimatedDuration, and serviceArea are required' });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');

    const newService = {
      title: title.trim(),
      category,
      description: description.trim(),
      image: image || 'https://images.unsplash.com/photo-1581092160607-ee22621dd758?w=800&auto=format&fit=crop&q=60',
      basePrice: Math.round(numericPrice * 100) / 100,
      estimatedDuration: estimatedDuration.trim(),
      serviceMode,
      serviceArea: serviceArea.trim(),
      technicianId: req.user.id,
      technicianName: req.user.name,
      technicianEmail: req.user.email,
      approvalStatus: 'pending',
      isAvailable: true,
      createdAt: new Date(),
    };

    const result = await servicesCollection.insertOne(newService);
    newService.id = result.insertedId.toString();
    newService._id = result.insertedId.toString();

    res.status(201).json({
      service: newService,
      message: 'Service listing created and submitted for moderation',
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/services-my - Technician read own services
app.get('/api/services-my', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const db = await getDb();
    const servicesCollection = db.collection('services');

    const query = {
      $or: [{ technicianId: req.user.id }, { technicianEmail: req.user.email }],
    };

    const services = await servicesCollection.find(query).sort({ createdAt: -1 }).toArray();

    const formatted = services.map((s) => ({
      ...s,
      id: s._id.toString(),
      _id: s._id.toString(),
      createdAt: s.createdAt instanceof Date ? s.createdAt.toISOString() : s.createdAt,
    }));

    res.status(200).json({ data: formatted });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/services/:id - Technician edit service (resets approval to pending)
app.patch('/api/services/:id', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(404).json({ error: 'Not Found', message: 'Invalid service ID format' });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');

    const existing = await servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Service not found' });
    }

    // Ownership check
    if (existing.technicianId !== req.user.id && existing.technicianEmail !== req.user.email) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not have permission to edit this service' });
    }

    const updates = {};
    const { title, description, category, image, basePrice, estimatedDuration, serviceMode, serviceArea } = req.body;

    if (title) updates.title = title.trim();
    if (description) updates.description = description.trim();
    if (category) updates.category = category;
    if (image) updates.image = image;
    if (basePrice !== undefined) updates.basePrice = Math.round(parseFloat(basePrice) * 100) / 100;
    if (estimatedDuration) updates.estimatedDuration = estimatedDuration.trim();
    if (serviceMode) updates.serviceMode = serviceMode;
    if (serviceArea) updates.serviceArea = serviceArea.trim();

    // Critical invariant: Content edits reset approval status to pending
    updates.approvalStatus = 'pending';
    updates.updatedAt = new Date();

    await servicesCollection.updateOne({ _id: new ObjectId(id) }, { $set: updates });
    const updated = await servicesCollection.findOne({ _id: new ObjectId(id) });

    res.status(200).json({
      service: {
        ...updated,
        id: updated._id.toString(),
        _id: updated._id.toString(),
      },
      message: 'Service updated and resubmitted for admin review',
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/services/:id/availability - Technician toggle availability (preserves approval)
app.patch('/api/services/:id/availability', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(404).json({ error: 'Not Found', message: 'Invalid service ID format' });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');

    const existing = await servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Service not found' });
    }

    if (existing.technicianId !== req.user.id && existing.technicianEmail !== req.user.email) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not own this service' });
    }

    const isAvailable = Boolean(req.body.isAvailable);
    await servicesCollection.updateOne({ _id: new ObjectId(id) }, { $set: { isAvailable, updatedAt: new Date() } });

    res.status(200).json({
      success: true,
      isAvailable,
      message: `Service is now ${isAvailable ? 'available' : 'hidden from public view'}`,
    });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/services/:id - Technician delete service
app.delete('/api/services/:id', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(404).json({ error: 'Not Found', message: 'Invalid service ID format' });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');

    const existing = await servicesCollection.findOne({ _id: new ObjectId(id) });
    if (!existing) {
      return res.status(404).json({ error: 'Not Found', message: 'Service not found' });
    }

    if (existing.technicianId !== req.user.id && existing.technicianEmail !== req.user.email) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not own this service' });
    }

    await servicesCollection.deleteOne({ _id: new ObjectId(id) });

    res.status(200).json({
      success: true,
      message: 'Service listing removed successfully',
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/services - Admin list all services for moderation
app.get('/api/admin/services', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const db = await getDb();
    const servicesCollection = db.collection('services');

    const query = {};
    if (req.query.status && req.query.status !== 'all') {
      query.approvalStatus = req.query.status;
    }

    const services = await servicesCollection.find(query).sort({ createdAt: -1 }).toArray();

    const formatted = services.map((s) => ({
      ...s,
      id: s._id.toString(),
      _id: s._id.toString(),
      createdAt: s.createdAt instanceof Date ? s.createdAt.toISOString() : s.createdAt,
    }));

    res.status(200).json({ data: formatted, total: formatted.length });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/admin/services/:id/approval - Admin approve or reject service
app.patch('/api/admin/services/:id/approval', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { approvalStatus } = req.body;

    if (!['approved', 'rejected', 'pending'].includes(approvalStatus)) {
      return res.status(400).json({ error: 'Validation Error', message: 'approvalStatus must be approved, rejected, or pending' });
    }

    if (!ObjectId.isValid(id)) {
      return res.status(404).json({ error: 'Not Found', message: 'Invalid service ID format' });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');

    const result = await servicesCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: { approvalStatus, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );

    if (!result) {
      return res.status(404).json({ error: 'Not Found', message: 'Service not found' });
    }

    res.status(200).json({
      service: {
        ...result,
        id: result._id.toString(),
        _id: result._id.toString(),
      },
      message: `Service status updated to ${approvalStatus}`,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/upload - Handle real image upload to ImgBB
app.post('/api/upload', verifyToken, async (req, res, next) => {
  try {
    const { image } = req.body;
    const apiKey = process.env.IMGBB_API_KEY;

    if (!image || typeof image !== 'string') {
      return res.status(400).json({ error: 'Validation Error', message: 'Image base64 data is required' });
    }

    if (!apiKey) {
      return res.status(503).json({
        error: 'Service Unavailable',
        message: 'Image upload service is currently unavailable; IMGBB_API_KEY is not configured in server environment',
      });
    }

    // Strictly decode base64 data and inspect real image magic bytes
    const base64Match = image.match(/^data:image\/(jpeg|jpg|png|webp);base64,(.+)$/);
    const base64Data = base64Match ? base64Match[2] : image.replace(/^data:image\/\w+;base64,/, '');

    let buffer;
    try {
      buffer = Buffer.from(base64Data, 'base64');
    } catch {
      return res.status(400).json({ error: 'Validation Error', message: 'Invalid base64 payload' });
    }

    if (!buffer || buffer.length === 0) {
      return res.status(400).json({ error: 'Validation Error', message: 'Empty image buffer received' });
    }

    if (buffer.length > 5 * 1024 * 1024) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Image size exceeds maximum limit of 5MB',
      });
    }

    // Inspect magic bytes: JPEG (FF D8 FF), PNG (89 50 4E 47), WebP (RIFF....WEBP)
    const isJpeg = buffer.length > 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;
    const isPng = buffer.length > 8 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47;
    const isWebp =
      buffer.length > 12 &&
      buffer.toString('ascii', 0, 4) === 'RIFF' &&
      buffer.toString('ascii', 8, 12) === 'WEBP';

    if (!isJpeg && !isPng && !isWebp) {
      return res.status(400).json({
        error: 'Validation Error',
        message: 'Uploaded file is not a supported image. Only authentic JPEG, PNG, and WebP files are accepted.',
      });
    }

    const formData = new FormData();
    formData.append('image', base64Data);

    const imgbbRes = await fetch(`https://api.imgbb.com/1/upload?key=${apiKey}`, {
      method: 'POST',
      body: formData,
    });

    const imgbbJson = await imgbbRes.json();
    if (!imgbbRes.ok || !imgbbJson.data) {
      return res.status(502).json({ error: 'Upload Failed', message: imgbbJson.error?.message || 'ImgBB upload rejected' });
    }

    res.status(200).json({
      url: imgbbJson.data.url,
      display_url: imgbbJson.data.display_url,
    });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// MILESTONE 4: BOOKINGS & REPAIR PIPELINE
// ==========================================

// POST /api/bookings - Customer submit repair booking request
app.post('/api/bookings', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const { serviceId, customerPhone, serviceAddress, preferredDate, problemDescription } = req.body;

    if (!serviceId || !ObjectId.isValid(serviceId)) {
      return res.status(400).json({ error: 'Validation Error', message: 'Valid service ID is required' });
    }

    if (!customerPhone || customerPhone.trim().length < 7) {
      return res.status(400).json({ error: 'Validation Error', message: 'Valid contact phone number is required (min 7 digits)' });
    }
    if (customerPhone.trim().length > 30) {
      return res.status(400).json({ error: 'Validation Error', message: 'Phone number exceeds maximum limit of 30 characters' });
    }

    if (!serviceAddress || serviceAddress.trim().length < 5) {
      return res.status(400).json({ error: 'Validation Error', message: 'Complete service address is required' });
    }
    if (serviceAddress.trim().length > 300) {
      return res.status(400).json({ error: 'Validation Error', message: 'Service address exceeds maximum limit of 300 characters' });
    }

    if (!problemDescription || problemDescription.trim().length < 20) {
      return res.status(400).json({ error: 'Validation Error', message: 'Detailed problem description is required (min 20 characters)' });
    }
    if (problemDescription.trim().length > 2000) {
      return res.status(400).json({ error: 'Validation Error', message: 'Problem description exceeds maximum limit of 2000 characters' });
    }

    const bookingDate = new Date(preferredDate);
    if (isNaN(bookingDate.getTime())) {
      return res.status(400).json({ error: 'Validation Error', message: 'Valid preferred service date is required' });
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    if (bookingDate < today) {
      return res.status(400).json({ error: 'Validation Error', message: 'Preferred service date must be today or in the future' });
    }

    const db = await getDb();
    const servicesCollection = db.collection('services');
    const bookingsCollection = db.collection('bookings');

    // Verify service exists, is approved, and available
    const service = await servicesCollection.findOne({
      _id: new ObjectId(serviceId),
      approvalStatus: 'approved',
      isAvailable: true,
    });

    if (!service) {
      return res.status(404).json({
        error: 'Not Found',
        message: 'This service is currently unavailable or unapproved for booking',
      });
    }

    // Atomic race-condition prevention: Check duplicate active booking by customer
    const existingActive = await bookingsCollection.findOne({
      customerEmail: req.user.email,
      serviceId: service._id.toString(),
      status: { $in: ['requested', 'accepted', 'in-progress'] },
    });

    if (existingActive) {
      return res.status(409).json({
        error: 'Conflict',
        message: 'You already have an active booking request for this service. Track its progress in your dashboard.',
      });
    }

    // Create trusted booking snapshot
    const newBooking = {
      serviceId: service._id.toString(),
      serviceTitle: service.title,
      serviceCategory: service.category,
      serviceImage: service.image,
      basePrice: service.basePrice,
      finalAmount: service.basePrice,
      technicianId: service.technicianId,
      technicianName: service.technicianName,
      technicianEmail: service.technicianEmail,
      customerId: req.user.id,
      customerName: req.user.name,
      customerEmail: req.user.email,
      customerPhone: customerPhone.trim(),
      serviceAddress: serviceAddress.trim(),
      preferredDate: bookingDate,
      problemDescription: problemDescription.trim(),
      status: 'requested',
      paymentStatus: 'unpaid',
      statusHistory: [
        {
          status: 'requested',
          timestamp: new Date(),
          changedBy: req.user.email,
          role: 'customer',
          note: 'Booking requested by customer',
        },
      ],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    let insertResult;
    try {
      insertResult = await bookingsCollection.insertOne(newBooking);
    } catch (insertErr) {
      if (insertErr.code === 11000 || insertErr.message?.includes('duplicate key')) {
        return res.status(409).json({
          error: 'Conflict',
          message: 'You already have an active booking request for this service. Track its progress in your dashboard.',
        });
      }
      throw insertErr;
    }

    newBooking.id = insertResult.insertedId.toString();
    newBooking._id = insertResult.insertedId.toString();

    res.status(201).json({
      booking: newBooking,
      message: 'Repair booking request submitted successfully',
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/bookings/my - Customer view own bookings
app.get('/api/bookings/my', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const bookings = await bookingsCollection
      .find({ customerEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    const formatted = bookings.map((b) => ({
      ...b,
      id: b._id.toString(),
      _id: b._id.toString(),
      preferredDate: b.preferredDate instanceof Date ? b.preferredDate.toISOString() : b.preferredDate,
      createdAt: b.createdAt instanceof Date ? b.createdAt.toISOString() : b.createdAt,
    }));

    res.status(200).json({ data: formatted });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/bookings/:id/cancel - Customer cancel booking (only allowed if status === 'requested')
app.patch('/api/bookings/:id/cancel', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(404).json({ error: 'Not Found', message: 'Invalid booking ID format' });
    }

    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
    if (!booking) {
      return res.status(404).json({ error: 'Not Found', message: 'Booking not found' });
    }

    // Ownership check
    if (booking.customerEmail !== req.user.email && booking.customerId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not own this booking' });
    }

    // Enforce terminal state and invariant
    if (booking.status !== 'requested') {
      return res.status(400).json({
        error: 'Bad Request',
        message: `Only pending requests can be cancelled. Current status is already ${booking.status}.`,
      });
    }

    const cancelNote = reason?.trim() || 'Booking cancelled by customer';
    const cancelResult = await bookingsCollection.updateOne(
      {
        _id: new ObjectId(id),
        status: 'requested',
        $or: [{ customerEmail: req.user.email }, { customerId: req.user.id }],
      },
      {
        $set: { status: 'cancelled', updatedAt: new Date() },
        $push: {
          statusHistory: {
            status: 'cancelled',
            timestamp: new Date(),
            changedBy: req.user.email,
            role: 'customer',
            note: cancelNote,
          },
        },
      }
    );

    if (cancelResult.matchedCount === 0) {
      return res.status(409).json({
        error: 'Conflict',
        message: 'Booking could not be cancelled. Status was modified concurrently or permission denied.',
      });
    }

    res.status(200).json({
      success: true,
      message: 'Booking request cancelled successfully',
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/bookings/technician - Technician get incoming booking requests
app.get('/api/bookings/technician', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const query = {
      $or: [{ technicianEmail: req.user.email }, { technicianId: req.user.id }],
    };

    if (req.query.status && req.query.status !== 'all') {
      query.status = req.query.status;
    }

    const bookings = await bookingsCollection.find(query).sort({ createdAt: -1 }).toArray();

    const formatted = bookings.map((b) => ({
      ...b,
      id: b._id.toString(),
      _id: b._id.toString(),
      preferredDate: b.preferredDate instanceof Date ? b.preferredDate.toISOString() : b.preferredDate,
      createdAt: b.createdAt instanceof Date ? b.createdAt.toISOString() : b.createdAt,
    }));

    res.status(200).json({ data: formatted });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/bookings/:id/status - Technician update booking status through strict lifecycle
app.patch('/api/bookings/:id/status', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { status: targetStatus, note, finalAmount } = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(404).json({ error: 'Not Found', message: 'Invalid booking ID format' });
    }

    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
    if (!booking) {
      return res.status(404).json({ error: 'Not Found', message: 'Booking not found' });
    }

    // Ownership check
    if (booking.technicianEmail !== req.user.email && booking.technicianId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You are not the assigned technician for this booking' });
    }

    // State machine transitions:
    // requested -> accepted | rejected
    // accepted -> in-progress
    // in-progress -> completed (requires positive finalAmount)
    const currentStatus = booking.status;
    const allowedTransitions = {
      requested: ['accepted', 'rejected'],
      accepted: ['in-progress'],
      'in-progress': ['completed'],
    };

    const validTargets = allowedTransitions[currentStatus] || [];
    if (!validTargets.includes(targetStatus)) {
      return res.status(400).json({
        error: 'Bad Request',
        message: `Cannot transition booking from '${currentStatus}' to '${targetStatus}'. Allowed: ${validTargets.join(', ') || 'none (terminal state)'}`,
      });
    }

    const updateFields = {
      status: targetStatus,
      updatedAt: new Date(),
    };

    if (targetStatus === 'completed') {
      const parsedAmount = parseFloat(finalAmount);
      if (isNaN(parsedAmount) || parsedAmount <= 0) {
        return res.status(400).json({
          error: 'Validation Error',
          message: 'Completing a repair job requires a positive final amount',
        });
      }
      updateFields.finalAmount = Math.round(parsedAmount * 100) / 100;
    }

    const historyEntry = {
      status: targetStatus,
      timestamp: new Date(),
      changedBy: req.user.email,
      role: 'technician',
      note: note?.trim() || `Status updated to ${targetStatus}`,
    };

    const updateResult = await bookingsCollection.updateOne(
      {
        _id: new ObjectId(id),
        status: currentStatus,
        $or: [{ technicianEmail: req.user.email }, { technicianId: req.user.id }],
      },
      {
        $set: updateFields,
        $push: { statusHistory: historyEntry },
      }
    );

    if (updateResult.matchedCount === 0) {
      return res.status(409).json({
        error: 'Conflict',
        message: `Booking could not be updated to '${targetStatus}'. Status was modified concurrently.`,
      });
    }

    const updated = await bookingsCollection.findOne({ _id: new ObjectId(id) });

    res.status(200).json({
      booking: {
        ...updated,
        id: updated._id.toString(),
        _id: updated._id.toString(),
      },
      message: `Booking status updated to ${targetStatus}`,
    });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// MILESTONE 5: DASHBOARDS, PROFILE & STATS
// ==========================================

// GET /api/stats/customer - Customer dashboard overview
app.get('/api/stats/customer', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const allBookings = await bookingsCollection
      .find({ customerEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    const totalBookings = allBookings.length;
    const activeBookings = allBookings.filter((b) => ['requested', 'accepted', 'in-progress'].includes(b.status)).length;
    const completedBookings = allBookings.filter((b) => b.status === 'completed').length;
    const totalSpent = allBookings
      .filter((b) => b.status === 'completed' && b.paymentStatus === 'paid')
      .reduce((sum, b) => sum + (b.finalAmount || b.basePrice || 0), 0);

    const recentBookings = allBookings.slice(0, 5).map((b) => ({
      id: b._id.toString(),
      serviceTitle: b.serviceTitle,
      technicianName: b.technicianName,
      status: b.status,
      paymentStatus: b.paymentStatus,
      finalAmount: b.finalAmount || b.basePrice,
      createdAt: b.createdAt,
    }));

    res.status(200).json({
      stats: {
        totalBookings,
        activeBookings,
        completedBookings,
        totalSpent: Math.round(totalSpent * 100) / 100,
        recentBookings,
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/stats/technician - Technician dashboard overview
app.get('/api/stats/technician', verifyToken, verifyTechnician, async (req, res, next) => {
  try {
    const db = await getDb();
    const bookingsCollection = db.collection('bookings');
    const servicesCollection = db.collection('services');

    const [bookings, services] = await Promise.all([
      bookingsCollection
        .find({ $or: [{ technicianEmail: req.user.email }, { technicianId: req.user.id }] })
        .sort({ createdAt: -1 })
        .toArray(),
      servicesCollection
        .find({ $or: [{ technicianEmail: req.user.email }, { technicianId: req.user.id }] })
        .toArray(),
    ]);

    const totalRequests = bookings.length;
    const pendingRequests = bookings.filter((b) => b.status === 'requested').length;
    const inProgress = bookings.filter((b) => b.status === 'in-progress').length;
    const completed = bookings.filter((b) => b.status === 'completed').length;
    const totalEarnings = bookings
      .filter((b) => b.status === 'completed' && b.paymentStatus === 'paid')
      .reduce((sum, b) => sum + (b.finalAmount || b.basePrice || 0), 0);

    const recentRequests = bookings.slice(0, 5).map((b) => ({
      id: b._id.toString(),
      serviceTitle: b.serviceTitle,
      customerName: b.customerName,
      customerPhone: b.customerPhone,
      status: b.status,
      paymentStatus: b.paymentStatus,
      finalAmount: b.finalAmount || b.basePrice,
      createdAt: b.createdAt,
    }));

    res.status(200).json({
      stats: {
        totalRequests,
        pendingRequests,
        inProgress,
        completed,
        totalServices: services.length,
        totalEarnings: Math.round(totalEarnings * 100) / 100,
        recentRequests,
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/stats/admin - Admin dashboard overview
app.get('/api/stats/admin', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const db = await getDb();
    const usersCollection = db.collection('user');
    const servicesCollection = db.collection('services');
    const bookingsCollection = db.collection('bookings');
    const paymentsCollection = db.collection('payments');

    const [users, services, bookings, payments] = await Promise.all([
      usersCollection.find({}, { projection: { role: 1 } }).toArray(),
      servicesCollection.find({}, { projection: { approvalStatus: 1 } }).toArray(),
      bookingsCollection.find({}).sort({ createdAt: -1 }).toArray(),
      paymentsCollection.find({ status: 'succeeded' }).toArray(),
    ]);

    const totalUsers = users.length;
    const customersCount = users.filter((u) => u.role === 'customer').length;
    const techniciansCount = users.filter((u) => u.role === 'technician').length;

    const totalServices = services.length;
    const pendingServicesCount = services.filter((s) => s.approvalStatus === 'pending').length;
    const approvedServicesCount = services.filter((s) => s.approvalStatus === 'approved').length;

    const totalBookings = bookings.length;
    const activeBookingsCount = bookings.filter((b) => ['requested', 'accepted', 'in-progress'].includes(b.status)).length;
    const completedBookingsCount = bookings.filter((b) => b.status === 'completed').length;

    const totalRevenue = payments.reduce((sum, p) => sum + (p.amount || 0), 0);

    const recentBookings = bookings.slice(0, 5).map((b) => ({
      id: b._id.toString(),
      serviceTitle: b.serviceTitle,
      customerEmail: b.customerEmail,
      technicianEmail: b.technicianEmail,
      status: b.status,
      finalAmount: b.finalAmount || b.basePrice,
      createdAt: b.createdAt,
    }));

    res.status(200).json({
      stats: {
        totalUsers,
        customersCount,
        techniciansCount,
        totalServices,
        pendingServicesCount,
        approvedServicesCount,
        totalBookings,
        activeBookingsCount,
        completedBookingsCount,
        totalRevenue: Math.round(totalRevenue * 100) / 100,
        recentBookings,
      },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/users - Admin list all registered users
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const db = await getDb();
    const usersCollection = db.collection('user');

    const users = await usersCollection
      .find({}, { projection: { password: 0 } })
      .sort({ createdAt: -1 })
      .toArray();

    const formatted = users.map((u) => ({
      id: u.id || u._id.toString(),
      _id: u._id.toString(),
      name: u.name,
      email: u.email,
      role: u.role || 'customer',
      image: u.image || null,
      phone: u.phone || null,
      serviceArea: u.serviceArea || u.area || null,
      createdAt: u.createdAt instanceof Date ? u.createdAt.toISOString() : u.createdAt,
    }));

    res.status(200).json({ data: formatted, total: formatted.length });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/admin/users/:id/role - Admin update user role
app.patch('/api/admin/users/:id/role', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    const allowedRoles = ['customer', 'technician', 'admin'];
    if (!role || !allowedRoles.includes(role)) {
      return res.status(400).json({ error: 'Validation Error', message: `Invalid role. Allowed: ${allowedRoles.join(', ')}` });
    }

    const db = await getDb();
    const usersCollection = db.collection('user');

    const query = [{ id }, { _id: id }];
    if (ObjectId.isValid(id)) {
      query.push({ _id: new ObjectId(id) });
    }

    const targetUser = await usersCollection.findOne({ $or: query });
    if (!targetUser) {
      return res.status(404).json({ error: 'Not Found', message: 'User not found' });
    }

    // Critical security invariant: Admins cannot change their own role!
    if (targetUser.email === req.user.email || targetUser.id === req.user.id || targetUser._id.toString() === req.user.id) {
      return res.status(400).json({ error: 'Forbidden', message: 'Admins cannot change their own role' });
    }

    await usersCollection.updateOne({ _id: targetUser._id }, { $set: { role, updatedAt: new Date() } });

    res.status(200).json({
      success: true,
      message: `User role updated to ${role}`,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/bookings - Admin view all platform bookings
app.get('/api/admin/bookings', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const query = {};
    if (req.query.status && req.query.status !== 'all') {
      query.status = req.query.status;
    }

    const bookings = await bookingsCollection.find(query).sort({ createdAt: -1 }).toArray();

    const formatted = bookings.map((b) => ({
      ...b,
      id: b._id.toString(),
      _id: b._id.toString(),
      preferredDate: b.preferredDate instanceof Date ? b.preferredDate.toISOString() : b.preferredDate,
      createdAt: b.createdAt instanceof Date ? b.createdAt.toISOString() : b.createdAt,
    }));

    res.status(200).json({ data: formatted, total: formatted.length });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/users/profile - Authenticated user update own profile
app.patch('/api/users/profile', verifyToken, async (req, res, next) => {
  try {
    const { name, phone, serviceArea, area, bio, image } = req.body;
    const db = await getDb();
    const usersCollection = db.collection('user');

    const query = [{ id: req.user.id }, { _id: req.user.id }];
    if (ObjectId.isValid(req.user.id)) {
      query.push({ _id: new ObjectId(req.user.id) });
    }

    const updates = { updatedAt: new Date() };
    if (name && typeof name === 'string') updates.name = name.trim();
    if (phone !== undefined) updates.phone = typeof phone === 'string' ? phone.trim() : phone;
    
    // Synchronize both area and serviceArea fields in tandem for full schema compatibility
    const resolvedArea = serviceArea !== undefined ? serviceArea : area;
    if (resolvedArea !== undefined) {
      const trimmedArea = typeof resolvedArea === 'string' ? resolvedArea.trim() : resolvedArea;
      updates.serviceArea = trimmedArea;
      updates.area = trimmedArea;
    }

    if (bio !== undefined) updates.bio = typeof bio === 'string' ? bio.trim() : bio;
    if (image !== undefined) updates.image = image;

    await usersCollection.updateOne({ $or: query }, { $set: updates });

    const updatedUser = await usersCollection.findOne({ $or: query });

    res.status(200).json({
      user: {
        id: updatedUser.id || updatedUser._id.toString(),
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role || 'customer',
        image: updatedUser.image || null,
        phone: updatedUser.phone || null,
        serviceArea: updatedUser.serviceArea || updatedUser.area || null,
        area: updatedUser.area || updatedUser.serviceArea || null,
        bio: updatedUser.bio || null,
      },
      message: 'Profile updated successfully',
    });
  } catch (err) {
    next(err);
  }
});

// ==========================================
// MILESTONE 6: STRIPE TEST PAYMENTS & WEBHOOKS
// ==========================================

// POST /api/payments/create-checkout-session - Customer create Stripe Checkout session
app.post('/api/payments/create-checkout-session', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const { bookingId } = req.body;

    if (!bookingId || !ObjectId.isValid(bookingId)) {
      return res.status(400).json({ error: 'Validation Error', message: 'Valid booking ID is required' });
    }

    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const booking = await bookingsCollection.findOne({ _id: new ObjectId(bookingId) });
    if (!booking) {
      return res.status(404).json({ error: 'Not Found', message: 'Booking not found' });
    }

    // Ownership check
    if (booking.customerEmail !== req.user.email && booking.customerId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not own this booking' });
    }

    // Pre-requisites: Must be completed and unpaid
    if (booking.status !== 'completed') {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Payment is only permitted after repair work is completed by the technician',
      });
    }

    if (booking.paymentStatus === 'paid') {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'This booking has already been paid in full',
      });
    }

    const payAmount = booking.finalAmount || booking.basePrice || 10;
    const amountInCents = Math.round(payAmount * 100);

    if (!stripe) {
      return res.status(503).json({
        error: 'Service Unavailable',
        message: 'Stripe payment gateway is not configured',
      });
    }

    // Reuse existing open Stripe checkout session if one was already issued for this booking
    if (booking.stripeSessionId) {
      try {
        const existingSession = await stripe.checkout.sessions.retrieve(booking.stripeSessionId);
        if (existingSession && existingSession.status === 'open' && existingSession.url) {
          return res.status(200).json({
            url: existingSession.url,
            sessionId: existingSession.id,
          });
        }
      } catch (err) {
        // If expired or retrieval error, proceed to create new session
      }
    }

    const clientOrigin = req.headers.origin || CORS_ORIGINS[0] || 'http://localhost:3000';

    const session = await stripe.checkout.sessions.create(
      {
        payment_method_types: ['card'],
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: `FixMate: ${booking.serviceTitle}`,
                description: `Completed repair service by ${booking.technicianName}`,
                images: booking.serviceImage ? [booking.serviceImage] : [],
              },
              unit_amount: amountInCents,
            },
            quantity: 1,
          },
        ],
        mode: 'payment',
        customer_email: req.user.email,
        client_reference_id: booking._id.toString(),
        metadata: {
          bookingId: booking._id.toString(),
          customerId: req.user.id,
          technicianEmail: booking.technicianEmail,
          serviceTitle: booking.serviceTitle,
        },
        success_url: `${clientOrigin}/payment/success?session_id={CHECKOUT_SESSION_ID}&booking_id=${booking._id.toString()}`,
        cancel_url: `${clientOrigin}/payment/cancel?booking_id=${booking._id.toString()}`,
      },
      {
        idempotencyKey: `checkout_${booking._id.toString()}_${amountInCents}`,
      }
    );

    await bookingsCollection.updateOne(
      { _id: new ObjectId(bookingId) },
      { $set: { stripeSessionId: session.id, updatedAt: new Date() } }
    );

    res.status(200).json({
      url: session.url,
      sessionId: session.id,
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/payments/verify - Customer verify Stripe session and fulfill payment
app.get('/api/payments/verify', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const { session_id, booking_id } = req.query;

    if (!session_id || !booking_id || !ObjectId.isValid(booking_id)) {
      return res.status(400).json({ error: 'Validation Error', message: 'session_id and valid booking_id are required' });
    }

    const db = await getDb();
    const bookingsCollection = db.collection('bookings');

    const bookingDoc = await bookingsCollection.findOne({ _id: new ObjectId(booking_id) });
    if (!bookingDoc) {
      return res.status(404).json({ error: 'Not Found', message: 'Booking not found' });
    }

    // Customer payment ownership verification
    if (bookingDoc.customerEmail !== req.user.email && bookingDoc.customerId !== req.user.id) {
      return res.status(403).json({ error: 'Forbidden', message: 'You do not own this booking' });
    }

    if (!stripe) {
      return res.status(503).json({ error: 'Service Unavailable', message: 'Stripe gateway not configured' });
    }

    const session = await stripe.checkout.sessions.retrieve(session_id);
    if (!session || session.payment_status !== 'paid') {
      return res.status(400).json({ error: 'Bad Request', message: 'Stripe session is not paid' });
    }

    const metaBookingId = session.metadata?.bookingId || session.client_reference_id;
    if (metaBookingId !== booking_id) {
      return res.status(400).json({ error: 'Bad Request', message: 'Session booking mismatch' });
    }

    const booking = await fulfillPaymentSession(session);

    if (!booking || booking.paymentStatus !== 'paid') {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Payment verification failed: session could not be fulfilled due to status or amount mismatch',
      });
    }

    res.status(200).json({
      success: true,
      booking,
      message: 'Payment verified and booking updated to paid',
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/payments/my - Customer view own payment transactions
app.get('/api/payments/my', verifyToken, verifyCustomer, async (req, res, next) => {
  try {
    const db = await getDb();
    const paymentsCollection = db.collection('payments');

    const payments = await paymentsCollection
      .find({ customerEmail: req.user.email })
      .sort({ createdAt: -1 })
      .toArray();

    const formatted = payments.map((p) => ({
      ...p,
      id: p._id.toString(),
      _id: p._id.toString(),
      createdAt: p.createdAt instanceof Date ? p.createdAt.toISOString() : p.createdAt,
    }));

    res.status(200).json({ data: formatted });
  } catch (err) {
    next(err);
  }
});

// GET /api/admin/payments - Admin view all transactions & calculate platform revenue
app.get('/api/admin/payments', verifyToken, verifyAdmin, async (req, res, next) => {
  try {
    const db = await getDb();
    const paymentsCollection = db.collection('payments');

    const payments = await paymentsCollection.find({}).sort({ createdAt: -1 }).toArray();

    const totalRevenue = payments.reduce((sum, p) => sum + (p.amount || 0), 0);

    const formatted = payments.map((p) => ({
      ...p,
      id: p._id.toString(),
      _id: p._id.toString(),
      createdAt: p.createdAt instanceof Date ? p.createdAt.toISOString() : p.createdAt,
    }));

    res.status(200).json({
      data: formatted,
      totalRevenue: Math.round(totalRevenue * 100) / 100,
      total: formatted.length,
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
  const server = app.listen(PORT, () => {
    console.log(`FixMate server running on port ${PORT}`);
  });

  const handleShutdown = async (signal) => {
    console.log(`Received ${signal}. Closing server and database connection pool...`);
    server.close(async () => {
      if (cachedClient) {
        await cachedClient.close().catch(() => {});
        console.log('MongoDB connection closed.');
      }
      process.exit(0);
    });
  };

  process.on('SIGINT', () => handleShutdown('SIGINT'));
  process.on('SIGTERM', () => handleShutdown('SIGTERM'));
}

export default app;
