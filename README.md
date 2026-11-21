# FixMate Server

FixMate backend API built with Node.js, Express, and MongoDB in a clean, high-performance architecture centered entirely in `index.js`. It powers the FixMate repair service marketplace with role-based access control, service management, repair booking state machine, and Stripe test-mode checkout workflows.

## Technology Stack

- **Runtime**: Node.js (ES Modules)
- **Framework**: Express 4
- **Database**: MongoDB Native Driver with connection pooling, cached client, and compound query indexing
- **Security**: Exact CORS origin validation (403 on disallowed origins), HS256 JWT authorization, role verification middleware
- **Payments**: Stripe Checkout Sessions with raw-body cryptographic webhook signature verification
- **Deployment**: Vercel Serverless Functions (`export default app`) or standalone containerized Node.js

## Architecture

The entire server runs cleanly from `index.js` without scattered helper scripts or nested directories, satisfying single-file runtime requirements:

```text
FixMate-Server/
├── index.js             # Consolidated Express server, routes, middleware, Stripe handlers, and database pool
├── package.json         # Dependencies and scripts
├── .gitignore           # Git ignore rules (strictly excludes environment files)
└── .vercelignore        # Vercel deployment exclusions
```

## Available Scripts

- `npm run dev`: Start local development server with file watching (`node --watch index.js`)
- `npm run start`: Start the production server (`node index.js`)
- `npm run check`: Verify syntax on `index.js` (`node --check index.js`)
- `npm test`: Run automated backend integration and domain tests (`node --test test/server.test.js`)

## API Endpoint Reference

### Public & Health Endpoints

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/` | Public | Service identification and version status |
| `GET` | `/health` | Public | Liveness check (independent of database) |
| `GET` | `/health/ready` | Public | Readiness check with database ping latency and memory stats |
| `GET` | `/api/services` | Public | List approved & available services with search, category/mode filter, sorting, and pagination |
| `GET` | `/api/services/:id` | Public | Get single approved and available service details |

### Authentication & Profile

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/me` | Authenticated | Current user profile projection |
| `PATCH` | `/api/users/profile` | Authenticated | Update user name, phone, area, bio, and image |
| `POST` | `/api/upload` | Authenticated | ImgBB image upload with secure base64 fallback |

### Technician Service Management

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/services` | Technician | Create new service (defaults to pending approval and active visibility) |
| `GET` | `/api/services-my` | Technician | View own service listings across all approval states |
| `PATCH` | `/api/services/:id` | Technician | Edit service details (resets approval status to pending) |
| `PATCH` | `/api/services/:id/availability` | Technician | Toggle visibility without resetting approval |
| `DELETE` | `/api/services/:id` | Technician | Remove owned service listing |

### Repair Bookings & Job Pipeline

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/bookings` | Customer | Submit repair request with duplicate race prevention and snapshot creation |
| `GET` | `/api/bookings/my` | Customer | List customer repair bookings with full status history audit trail |
| `PATCH` | `/api/bookings/:id/cancel` | Customer | Cancel request (allowed strictly while status is requested) |
| `GET` | `/api/bookings/technician` | Technician | Incoming booking queue assigned to technician |
| `PATCH` | `/api/bookings/:id/status` | Technician | Transition lifecycle: requested -> accepted/rejected, accepted -> in-progress, in-progress -> completed (requires final amount) |

### Statistics & Administration

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/api/stats/customer` | Customer | Personal repair metrics and spending totals |
| `GET` | `/api/stats/technician` | Technician | Active queue counts and settled revenue |
| `GET` | `/api/stats/admin` | Admin | Global counts, active repairs, and gross platform volume |
| `GET` | `/api/admin/services` | Admin | Service moderation queue with status filter |
| `PATCH` | `/api/admin/services/:id/approval` | Admin | Approve or reject submitted service listings |
| `GET` | `/api/admin/users` | Admin | List all registered users |
| `PATCH` | `/api/admin/users/:id/role` | Admin | Update user role (prevents admin self-demotion) |
| `GET` | `/api/admin/bookings` | Admin | Global surveillance of all platform bookings |

### Stripe Payments & Webhooks

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `POST` | `/api/payments/create-checkout-session` | Customer | Create Stripe Checkout session for completed unpaid booking |
| `GET` | `/api/payments/verify` | Customer | Verify Stripe session and execute idempotent payment fulfillment |
| `POST` | `/api/payments/webhook` | Stripe | Raw body cryptographic webhook handler for `checkout.session.completed` |
| `GET` | `/api/payments/my` | Customer | View customer receipt history |
| `GET` | `/api/admin/payments` | Admin | Audited platform transaction ledger and gross revenue calculation |

## Environment Variables

Configure these variables in your deployment environment. Never commit `.env` files to Git.

| Variable | Description |
| --- | --- |
| `PORT` | Local listener port (defaults to `5000`) |
| `MONGODB_URI` | MongoDB connection string (Atlas or local replica set) |
| `MONGODB_DBNAME` | Database name (e.g. `fixmate-db`) |
| `CORS_ORIGINS` | Comma-separated allowed frontend origins |
| `JWT_SECRET` | Secret key used to verify HS256 API tokens |
| `JWT_ISSUER` | Expected token issuer |
| `JWT_AUDIENCE` | Expected token audience (`fixmate-api`) |
| `STRIPE_SECRET_KEY` | Stripe test secret API key (`sk_test_...`) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (`whsec_...`) |
| `IMGBB_API_KEY` | Optional ImgBB API key for image hosting |
