// src/controllers/uploadController.ts
import { v2 as cloudinary } from 'cloudinary';
import { Request, Response } from 'express';
import streamifier from 'streamifier';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME!,
    api_key: process.env.CLOUDINARY_API_KEY!,
    api_secret: process.env.CLOUDINARY_API_SECRET!,
});

export const uploadToCloudinary = (req: Request, res: Response) => {
    log("進入上傳")
    if (!req.file) {
        res.status(400).json({ error: '未提供圖片' });
        return;
    }

    const MAX_SIZE = 1 * 1024 * 1024;

    if (req.file.size > MAX_SIZE) {
        res.status(400).json({
            error: '圖片過大，請選擇小於 1MB 的圖片',
        });
        return;
    }

    const stream = cloudinary.uploader.upload_stream(
        {
            folder: 'userheadshot',
        },
        (error, result) => {
            if (error || !result) {
                logError('❌ Cloudinary 上傳錯誤', error);
                res.status(500).json({ error: '圖片上傳失敗' });
                return;
            }

            log("✅ 上傳成功：" + result.secure_url);
            log('🆔 使用者 ID:', req.user?.id);
            log('👤 使用者帳號:', req.user?.account);
            log('🧑‍💻 使用者角色:', req.user?.role);
            res.json({
                url: result.secure_url,
                public_id: result.public_id,
            });
        },
    );

    streamifier.createReadStream(req.file.buffer).pipe(stream);
};
