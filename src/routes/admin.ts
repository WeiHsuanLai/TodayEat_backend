// routes/admin.ts
import express from 'express';
import { getAllLoginLogs } from '../controllers/adminLog';
import { adminMiddleware } from '../middleware/adminMiddleware';

const router = express.Router();

router.get('/login-logs', adminMiddleware, getAllLoginLogs);

export default router;
