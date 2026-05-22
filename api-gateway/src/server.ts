import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import dotenv from 'dotenv';
import { createClient } from 'redis';
import { v4 as uuidv4 } from 'uuid';
import { validateAuditTarget } from './middleware/validator';

// 1. Setup Environment
dotenv.config();

const PORT = process.env.PORT || 4000;
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';
const REDIS_QUEUE_KEY = process.env.REDIS_QUEUE_KEY || 'shadowaudit:queue';
const REDIS_RESULTS_CHANNEL = process.env.REDIS_RESULTS_CHANNEL || 'shadowaudit:results';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';

const app = express();
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json());

const server = http.createServer(app);

// 2. Setup Socket.io
const io = new Server(server, {
  cors: {
    origin: CORS_ORIGIN,
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// 3. Initialize Redis Clients (Client and Subscriber)
const redisClient = createClient({ url: REDIS_URL });
const redisSubscriber = redisClient.duplicate();

redisClient.on('error', (err) => console.error('[Redis Client Error]', err));
redisSubscriber.on('error', (err) => console.error('[Redis Subscriber Error]', err));

// Define interfaces for typings
interface ScanJob {
  auditId: string;
  target: string;
  status: 'queued' | 'scanning' | 'completed' | 'failed';
  createdAt: string;
}

interface ScanLogPayload {
  auditId: string;
  stage: 'queued' | 'scanning' | 'completed' | 'failed' | 'log';
  message: string;
  data?: any;
  timestamp: string;
}

// 4. REST API Endpoint
app.post('/api/audit/scan', validateAuditTarget, async (req: express.Request, res: express.Response) => {
  const target = req.body.sanitizedTarget as string;
  const auditId = uuidv4();

  try {
    const job: ScanJob = {
      auditId,
      target,
      status: 'queued',
      createdAt: new Date().toISOString()
    };

    // Push the audit job to the Redis queue list (rpush)
    await redisClient.rPush(REDIS_QUEUE_KEY, JSON.stringify(job));
    console.log(`[Queue] Scan enqueued successfully. Audit ID: ${auditId} | Target: ${target}`);

    // Broadcast the initial queued status via WebSockets
    const initialLog: ScanLogPayload = {
      auditId,
      stage: 'queued',
      message: `Audit scan queued successfully. ID: ${auditId}`,
      timestamp: new Date().toISOString()
    };
    
    // Broadcast to room
    io.to(auditId).emit('scan_update', initialLog);

    res.status(202).json({
      status: 'Accepted',
      auditId,
      message: 'Security audit scan accepted and enqueued.',
      target
    });
  } catch (error) {
    console.error('[API Error] Failed to enqueue scan:', error);
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to process security scan request.'
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// 5. Setup WebSockets Rooms for Live Scanning Logs
io.on('connection', (socket) => {
  console.log(`[Socket.io] Client connected: ${socket.id}`);

  // Client joins a room specific to their audit scan to prevent data leakage
  socket.on('join_audit', (auditId: string) => {
    if (auditId && typeof auditId === 'string') {
      socket.join(auditId);
      console.log(`[Socket.io] Socket ${socket.id} joined scan room: ${auditId}`);
    }
  });

  socket.on('disconnect', () => {
    console.log(`[Socket.io] Client disconnected: ${socket.id}`);
  });
});

// 6. Connect to Redis & Subscribe to Results Channel
const startServer = async () => {
  try {
    await redisClient.connect();
    console.log('[Redis] Connected as client successfully.');

    await redisSubscriber.connect();
    console.log('[Redis] Connected as subscriber successfully.');

    // Subscribe to results channel from the Python worker
    await redisSubscriber.subscribe(REDIS_RESULTS_CHANNEL, (message: string) => {
      try {
        const payload = JSON.parse(message) as ScanLogPayload;
        const { auditId, stage, message: logMsg } = payload;
        
        console.log(`[Subscriber] Update received for scan ${auditId} [${stage}]: ${logMsg}`);
        
        // Emit the structured logs directly to the respective Socket.io room
        io.to(auditId).emit('scan_update', payload);
      } catch (err) {
        console.error('[Subscriber Error] Failed to parse Pub/Sub payload:', err);
      }
    });

    server.listen(PORT, () => {
      console.log(`\n======================================================`);
      console.log(`   SHADOWAUDIT API GATEWAY (SecOps Orchester)`);
      console.log(`   Running on http://localhost:${PORT}`);
      console.log(`   Redis connection URL: ${REDIS_URL}`);
      console.log(`======================================================\n`);
    });
  } catch (error) {
    console.error('Fatal initialization error:', error);
    process.exit(1);
  }
};

startServer();
