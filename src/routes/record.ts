import express from 'express';
import {
    drawFood,
    getTodayFoodDraws,
    getFoodDrawsByDate,
    getAllFoodDraws
} from '../controllers/record';

import { authMiddleware } from '../middleware/auth';

const router = express.Router();

// 🔐 套用 authMiddleware 確保只有登入者能使用這些 API
router.post('/food-draw', authMiddleware, drawFood);
router.get('/food-draw/all', authMiddleware, getAllFoodDraws);
router.get('/food-draw/today', authMiddleware, getTodayFoodDraws);
router.get('/food-draw/:date', authMiddleware, getFoodDrawsByDate);

export default router;
