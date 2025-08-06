// src\routes\auth.ts
import express from 'express';
import { getCaptcha, verifyCaptcha } from '../controllers/auth';

const router = express.Router();

router.get('/captcha', getCaptcha);
router.post('/captcha', verifyCaptcha);

export default router;