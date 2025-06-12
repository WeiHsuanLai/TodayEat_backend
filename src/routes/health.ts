// routes/health.ts
import { Router } from 'express';
import { StatusCodes } from 'http-status-codes';

const router = Router();

router.get('/', (req, res) => {
    log("有連到伺服器");
    res.status(StatusCodes.OK).json({
        success: true,
        status: 'UP',
        timestamp: new Date().toISOString(),
    });
});

export default router;
