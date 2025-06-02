import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/user';
import { log } from 'console';

interface DecodedUser {
    id: string;
    account: string;
    role: number;
    iat?: number;
    exp?: number;
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
        const user = await User.findById(decoded.id);
        if (!user || !Array.isArray(user.tokens) || !user.tokens.includes(token)) {
            log(`驗證失敗：user=${!!user} tokenInList=${user?.tokens.includes(token)}`);
            res.status(401).json({
                success: false,
                message: '登入已失效',
                reason: 'invalid_token',
            });
            return
        }
        req.user = decoded;
        next();
    } catch (err: unknown) {
        logError('[token 錯誤]', err);

        if (err instanceof jwt.TokenExpiredError) {
            res.status(401).json({ success: false, message: 'token 已過期，請重新登入' });
        } else {
            res.status(401).json({ success: false, message: 'token 驗證失敗' });
        }
    }

};
