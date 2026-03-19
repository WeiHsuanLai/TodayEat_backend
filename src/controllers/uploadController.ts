// src/controllers/uploadController.ts
import { v2 as cloudinary } from 'cloudinary';
import { Request, Response } from 'express';
import streamifier from 'streamifier';
import User from '../models/user';

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

    try {
        const stream = cloudinary.uploader.upload_stream(
            {
                folder: 'userheadshot',
            },
            async (error, result) => {
                if (error || !result) {
                    logError('❌ Cloudinary 上傳錯誤', error);
                    return res.status(500).json({ error: '圖片上傳失敗' });
                }

                log("✅ 上傳成功：" + result.secure_url);
                log('🆔 使用者 ID:', req.user?.id);

                try {
                    // 1. 取得目前使用者，確認是否有舊的 avatarPublicId
                    const user = await User.findById(req.user!.id);
                    
                    if (user && user.avatarPublicId) {
                        log(`🗑️ 正在刪除舊圖片：${user.avatarPublicId}`);
                        // 2. 刪除 Cloudinary 上的舊圖片
                        await cloudinary.uploader.destroy(user.avatarPublicId);
                    }

                    // 3. 更新資料庫（同時儲存 URL 與 Public ID）
                    await User.findByIdAndUpdate(req.user!.id, {
                        avatar: result.secure_url,
                        avatarPublicId: result.public_id,
                    });

                    res.json({
                        url: result.secure_url,
                        public_id: result.public_id,
                    });
                } catch (dbError) {
                    logError('❌ 處理大頭貼更新流程失敗', dbError);
                    res.status(500).json({ error: '圖片處理異常' });
                }
            },
        );

        streamifier.createReadStream(req.file.buffer).pipe(stream);
    } catch (err) {
        logError('❌ 上傳流程異常', err);
        res.status(500).json({ error: '圖片處理異常' });
    }
};
