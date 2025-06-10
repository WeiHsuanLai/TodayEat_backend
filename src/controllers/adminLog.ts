import { Request, Response } from 'express';
import LoginLog from '../models/LoginLog';
import '../models/user'; 

export const getAllLoginLogs = async (req: Request, res: Response) => {
    try {
        const logs = await LoginLog.find({})
        .populate('userId', 'account email role') // 可選：顯示帳號資訊
        .sort({ createdAt: -1 })
        .limit(100);

        res.json({ success: true, logs });

    } catch (err) {
        console.error('[getAllLoginLogs 錯誤]', err);
        res.status(500).json({ success: false, message: '無法取得登入紀錄' });
    }
};
