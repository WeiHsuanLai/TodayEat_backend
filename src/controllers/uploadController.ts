// src/controllers/uploadController.ts
import { v2 as cloudinary } from 'cloudinary';
import { Request, Response } from 'express';
import streamifier from 'streamifier';

export const uploadToCloudinary = (req: Request, res: Response) => {
    if (!req.file) {
        res.status(400).json({ error: '未提供圖片' });
        return;
    }

    const MAX_SIZE = 5 * 1024 * 1024;

    if (req.file.size > MAX_SIZE) {
        res.status(400).json({
            error: '圖片過大，請選擇小於 5MB 的圖片',
        });
        return;
    }

    const stream = cloudinary.uploader.upload_stream(
        {
            folder: 'userheadshot',
        },
        (error, result) => {
            if (error || !result) {
                console.error('❌ Cloudinary 上傳錯誤', error);
                res.status(500).json({ error: '圖片上傳失敗' });
                return;
            }

            res.json({
                url: result.secure_url,
                public_id: result.public_id,
            });
        },
    );

    streamifier.createReadStream(req.file.buffer).pipe(stream);
};
