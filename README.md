# FixMate Server

FixMate backend API built with Node.js, Express, and MongoDB in a clean, unified architecture (`index.js`). It provides RESTful endpoints for repair services, health monitoring, session-to-API JWT authorization, and future booking and payment workflows.

## Technology Stack

- **Runtime**: Node.js (ES Modules)
- **Framework**: Express 4
- **Database**: MongoDB Native Driver with connection pooling and caching
- **Security**: Strict CORS origin allowlist, centralized JSON error handling, HS256 JWT authorization
- **Deployment Target**: Vercel Serverless Functions

## Architecture

The entire server runs from `index.js`, enabling both standalone local execution with `node index.js` and seamless serverless hosting on Vercel by exporting the default Express application.

```text
FixMate-Server/
├── index.js             # Consolidated Express server, routes, middleware, and database pool
├── package.json         # Dependencies and scripts
├── .gitignore           # Git ignore rules (strictly excludes environment files)
└── .vercelignore        # Vercel deployment exclusions
```

## Available Scripts

- `npm run dev`: Start local development server with file watching (`node --watch index.js`)
- `npm run start`: Start the production server (`node index.js`)
- `npm run check`: Check JavaScript syntax on `index.js`

## API Endpoints

| Method | Endpoint | Access | Description |
| --- | --- | --- | --- |
| `GET` | `/` | Public | Service identification and status |
| `GET` | `/health` | Public | Liveness check (independent of database) |
| `GET` | `/health/ready` | Public | Readiness check (pings MongoDB) |
| `GET` | `/api/services` | Public | List approved and available services (newest first, bounded limit) |
| `GET` | `/api/services/:id` | Public | Get single approved service by ID |
| `GET` | `/api/me` | Authenticated | Safe user profile projection from database using Bearer JWT |

## Environment Variables

Configure these variables in your deployment environment. Never commit `.env` files to source control.

| Variable | Description |
| --- | --- |
| `PORT` | Local listener port (defaults to `5000`) |
| `MONGODB_URI` | MongoDB Atlas connection string |
| `MONGODB_DBNAME` | Database name (e.g. `fixmate-db`) |
| `CLIENT_URL` | Frontend origin (e.g. `http://localhost:3000` or production domain) |
| `CORS_ORIGINS` | Comma-separated list of allowed browser origins |
| `JWT_SECRET` | 32+ byte cryptographic key for HS256 JWT verification |
| `JWT_ISSUER` | Expected JWT issuer (must match frontend origin) |
| `JWT_AUDIENCE` | Expected JWT audience (`fixmate-api`) |
| `STRIPE_SECRET_KEY` | Stripe secret key (for future payment phase) |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret (for future payment phase) |
| `IMGBB_API_KEY` | ImgBB API key (for future image upload phase) |

## Vercel Deployment

1. Import the `CodeWithTanim/FixMate-Server` repository in Vercel.
2. Set Root Directory to `.`.
3. Choose Node.js LTS version.
4. Add all required environment variables in Vercel Project Settings.
5. Deploy and verify `/health` and `/health/ready`.
