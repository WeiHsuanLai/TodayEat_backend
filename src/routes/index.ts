import { Router } from 'express';
import user from './user';
import admin from './admin';
import health from './health';
import upload from './upload';
import places from './places';

const router = Router();

router.use('/user', user);
router.use('/admin', admin);
router.use('/health', health);
router.use('/upload', upload);
router.use('/places', places);

export default router;