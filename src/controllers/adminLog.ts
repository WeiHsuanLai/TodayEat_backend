import { Request, Response } from 'express';
import LoginLog from '../models/LoginLog';
import VisitorLog from '../models/VisitorLog';
import '../models/user';
import mongoose from 'mongoose';

interface PopulatedUser {
    _id: mongoose.Types.ObjectId;
    account: string;
    email: string;
    role: number;
}

export const getAllLoginLogs = async (req: Request, res: Response) => {
    try {
        // 取得查詢參數（來自 URL）
        const { keyword, from, to, limit, sort } = req.query;

        // 預設為最新在前
        const sortDirection = (sort === 'asc' || sort === 'desc') ? (sort === 'asc' ? 1 : -1) : -1;

        // 定義篩選條件的型別（擴充性佳，支援多欄位）
        interface LoginLogFilter extends Record<string, unknown> {
            $or?: Array<Record<string, unknown>>;
            timestamp?: {
                $gte?: Date;
                $lte?: Date;
            };
        }

        const filter: LoginLogFilter = {};

        // 若有關鍵字則模糊搜尋 IP 或地理位置
        if (keyword) {
            filter.$or = [
                { ip: { $regex: keyword, $options: 'i' } },
                { location: { $regex: keyword, $options: 'i' } },
            ];
        }

        // 將 from/to 字串轉換為有效 Date（無效則略過）
        const parseDate = (value?: string): Date | undefined => {
            const date = new Date(value || '');
            return isNaN(date.getTime()) ? undefined : date;
        };

        const fromDate = parseDate(from as string);
        const toDate = parseDate(to as string);

        // 若有任一時間存在則設定 createdAt 篩選區間
        if (fromDate || toDate) {
            filter.timestamp = {};
            if (fromDate) filter.timestamp.$gte = fromDate;
            if (toDate) filter.timestamp.$lte = toDate;
        }

        // 限制最大回傳筆數，避免過度查詢（上限 500）
        const max = Math.min(Number(limit) || 100, 500);
        // 查詢登入紀錄，依建立時間倒序排列，並帶出 userId 的部分資訊
        const rawLogs = await LoginLog.find(filter)
            .populate('userId', 'account email role')
            .sort({ timestamp: sortDirection })
            .limit(max)
            .lean();

        // 將 userId 扁平化，讓 account 直接出現在第一層
        const logs = rawLogs.map(log => {
            const user = log.userId as unknown as PopulatedUser;
            return {
                ...log,
                account: user?.account,
                email: user?.email,
                role: user?.role,
                userId: user?._id || log.userId
            };
        });

        // 成功回傳資料
        res.json({ success: true, logs });
    } catch (err) {
        console.error('[getAllLoginLogs 錯誤]', err);
        res.status(500).json({
            success: false,
            message: '無法取得登入紀錄',
            error: err instanceof Error ? err.message : String(err),
        });
    }
};

/**
 * 取得公開統計資訊，如今日訪客計數
 */
export const getPublicStats = async (_req: Request, res: Response) => {
    try {
        // 取得今日凌晨 00:00 的時間
        const startOfToday = new Date();
        startOfToday.setHours(0, 0, 0, 0);

        // 僅統計今日的紀錄
        const count = await VisitorLog.countDocuments({
            timestamp: { $gte: startOfToday }
        });

        res.json({
            success: true,
            visitorCount: count,
        });
    } catch (err) {
        console.error('[getPublicStats 錯誤]', err);
        res.status(500).json({
            success: false,
            message: '無法取得統計資訊',
            error: err instanceof Error ? err.message : String(err),
        });
    }
};
