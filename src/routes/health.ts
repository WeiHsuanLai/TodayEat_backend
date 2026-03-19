// routes/health.ts
import { Router } from 'express';
import { StatusCodes } from 'http-status-codes';
import { getPublicStats } from '../controllers/adminLog';

const router = Router();

router.get('/', (req, res) => {
    log("有連到伺服器");
    res.status(StatusCodes.OK).json({
        success: true,
        status: 'UP',
        timestamp: new Date().toISOString(),
    });
});

router.get('/visitor-count', getPublicStats);

export default router;
