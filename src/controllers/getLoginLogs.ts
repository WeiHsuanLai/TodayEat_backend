import LoginLog from "../models/LoginLog";
import { Request, Response } from 'express';

interface AuthenticatedRequest extends Request {
    user?: {
        id: string;
        account: string;
        role: number;
        avatar: string;
    };
}

export const getLoginLogs = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.id;

        if (!userId) {
            res.status(401).json({ success: false, message: req.t('未授權') });
            return;
        }

        const rawLogs = await LoginLog.find({ userId })
            .populate('userId', 'account')
            .sort({ timestamp: -1 })
            .limit(50)
            .lean();

        const logs = rawLogs.map(log => ({
            ...log,
            account: (log.userId as any)?.account,
            userId: (log.userId as any)?._id || log.userId
        }));

        res.json({ success: true, logs });
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (err) {
        res.status(500).json({ success: false, message: req.t('取得登入紀錄失敗') });
    }
};
