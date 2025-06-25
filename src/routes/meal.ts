import { Router } from 'express';
import { getAllMealPeriodPresets } from '../controllers/meal';

const router = Router();

router.get('/meal-period-presets', getAllMealPeriodPresets);

export default router;
