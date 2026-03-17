// src\routes\index.ts
import { Router } from 'express';
import user from './user';
import admin from './admin';
import health from './health';
import upload from './upload';
import places from './places';
import auth from './auth';
import dishes from './dish';
import foodRecords from './foodRecord';

const router = Router();

router.use('/user', user);
router.use('/admin', admin);
router.use('/health', health);
router.use('/upload', upload);
router.use('/places', places);
router.use('/auth', auth);
router.use('/dishes', dishes);
router.use('/food-records', foodRecords);

export default router;