import { Request, Response } from 'express';
import LoginLog from '../models/LoginLog';
import '../models/user';

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
        const logs = await LoginLog.find(filter)
            .populate('userId', 'account email role')
            .sort({ timestamp: sortDirection })
            .limit(max);

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
