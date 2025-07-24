// src/routes/upload.ts
import express from 'express';
import multer from 'multer';
import { uploadToCloudinary } from '../controllers/uploadController';
import { authMiddleware } from '../middleware/auth';

const router = express.Router();

// 設定 multer，限制檔案大小為 5MB
const upload = multer({
    limits: { fileSize: 1 * 1024 * 1024 },
});

router.post('/upload', authMiddleware, (req, res, next) => {
    upload.single('file')(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({
                success: false,
                message: '❌ 檔案超過 1MB 限制',
            });
        } else if (err) {
            // 其他錯誤
            return res.status(400).json({
                success: false,
                message: `發生錯誤：${err.message}`,
            });
        }
        next(); // 若無錯誤則繼續執行 uploadToCloudinary
    });
}, uploadToCloudinary);


export default router;
