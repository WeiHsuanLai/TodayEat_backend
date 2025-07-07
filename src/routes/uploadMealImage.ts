// src/routes/uploadMealImage.ts
import express from 'express';
import multer from 'multer';
import { uploadMealImage } from '../controllers/uploadMealImage';
import { authMiddleware } from '../middleware/auth';

const router = express.Router();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 1 * 1024 * 1024 },
});

router.post(
    '/meal-image',
    authMiddleware,
    (req, res, next) => {
        upload.single('file')(req, res, (err) => {
            if (err) {
                const message = err.code === 'LIMIT_FILE_SIZE'
                    ? '檔案過大，請小於 1MB'
                    : `上傳錯誤：${err.message}`;
                res.status(400).json({ error: message });
                return;
            }
            next();
        });
    },
    uploadMealImage
);

export default router;
