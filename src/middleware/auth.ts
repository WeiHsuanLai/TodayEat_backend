import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

interface DecodedUser {
    id: string;
    account: string;
    role: number;
}

// 擴充 req 物件（TypeScript 用）
declare module 'express-serve-static-core' {
    interface Request {
        user?: DecodedUser;
    }
}

export const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization; //檢查標頭

    // 沒帶 token
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ success: false, message: '未提供 token' });
        return;
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as DecodedUser;
        req.user = decoded;
        next();
    } catch (err) {
        console.error('[發生錯誤]', err);
        res.status(401).json({ success: false, message: 'token 驗證失敗' });
    }
};
