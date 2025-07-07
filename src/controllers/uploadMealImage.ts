// src/controllers/uploadMealImage.ts
import { v2 as cloudinary } from 'cloudinary';
import { Request, Response } from 'express';
import streamifier from 'streamifier';
import { CuisineType } from '../models/CuisineType';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME!,
    api_key: process.env.CLOUDINARY_API_KEY!,
    api_secret: process.env.CLOUDINARY_API_SECRET!,
});

export const uploadMealImage = async (req: Request, res: Response) => {
    const { label } = req.body;
    
    if (!label) {
        res.status(400).json({ error: '請提供分類名稱（label）' });
        return;
    }

    if (!req.file) {
        res.status(400).json({ error: '未提供圖片' });
        return;
    }

    const MAX_SIZE = 1 * 1024 * 1024;
    if (req.file.size > MAX_SIZE) {
        res.status(400).json({ error: '圖片超過 1MB 限制' });
        return;
    }

    try {
        const stream = cloudinary.uploader.upload_stream(
            { folder: 'meal-category' },
            async (error, result) => {
                if (error || !result) {
                    console.error('❌ Cloudinary 上傳失敗:', error);
                    res.status(500).json({ error: '圖片上傳失敗' });
                    return;
                }

                const updated = await CuisineType.findOneAndUpdate(
                    { label },
                    { imageUrl: result.secure_url },
                    { new: true }
                );

                if (!updated) {
                    res.status(404).json({ error: `找不到分類：${label}` });
                    return;
                }

                res.json({
                    success: true,
                    message: '圖片上傳並更新成功',
                    url: result.secure_url,
                    updated,
                });
            }
        );

        streamifier.createReadStream(req.file.buffer).pipe(stream);
    } catch (err) {
        console.error('❌ 上傳流程錯誤:', err);
        res.status(500).json({ error: '圖片處理錯誤' });
    }
};
