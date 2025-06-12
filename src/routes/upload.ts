// src/routes/upload.ts
import express from 'express';
import multer from 'multer';
import { uploadToCloudinary  } from '../controllers/uploadController';

const router = express.Router();

// 設定 multer，限制檔案大小為 5MB
const upload = multer({
  limits: { fileSize: 5 * 1024 * 1024 },
});

router.post('/upload', upload.single('file'), uploadToCloudinary);

export default router;
