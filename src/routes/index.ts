import { Router } from 'express';
import user from './user';
import admin from './admin';
import health from './health';
import upload from './upload';
import record from './record';
import cuisineTypes from './cuisineType';
import mealPresets from './mealPeriodPreset';
import places from './places';

const router = Router();

router.use('/user', user);
router.use('/admin', admin);
router.use('/health', health);
router.use('/upload', upload);
router.use('/record', record);
router.use('/cuisineTypes', cuisineTypes);
router.use('/mealPresets', mealPresets);
router.use('/places', places);

export default router;