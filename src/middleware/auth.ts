import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import User from '../models/user';

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

// 使用者驗證中介層
export const authMiddleware = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;
    const tokenFromHeader = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : undefined;
    const tokenFromAltHeader = req.headers['x-access-token'];

    // 🧠 優先使用 Authorization，其次使用 x-access-token
    const token = tokenFromHeader || tokenFromAltHeader;

    // ❌ 沒帶 token
    if (!token) {
        log("沒帶token")
        res.status(403).json({
            success: false,
            message: req.t('禁止存取，缺少有效憑證'),
            reason: 'missing_or_invalid_token_format',
        });
        return;
    }

    // ✅ 類型驗證：必須是 string
    if (typeof token !== 'string') {
        res.status(403).json({
            success: false,
            message: req.t('Token 類型錯誤'),
            reason: 'token_not_string',
        });
        return
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as DecodedUser;
        const user = await User.findById(decoded.id);
        if (!user || !Array.isArray(user.tokens) || !(user.tokens as string[]).includes(token)) {
            log(`驗證失敗：user=${!!user} tokenInList=${user?.tokens.includes(token)}`);
            res.status(401).json({
                success: false,
                message: req.t('登入已失效'),
                reason: 'invalid_token',
            });
            return
        }

        // ✅ 多重登入控制：只允許最新一筆 token 有效
        const lastToken = user.tokens[user.tokens.length - 1];
        if (token !== lastToken) {
            res.status(401).json({
                success: false,
                message: req.t('此 token 已被取代，請重新登入'),
                reason: 'token_superseded',
            });
            return
        }

        req.user = decoded;
        next();
    } catch (err: unknown) {
        logError(`[token 錯誤: ${err instanceof Error ? err.message : '未知錯誤'}]`, err);

        if (err instanceof jwt.TokenExpiredError) {
            res.status(401).json({
                success: false,
                message: req.t('token 已過期，請重新登入'),
                reason: 'token_expired',
            });
            return
        }

        res.status(401).json({
            success: false,
            message: req.t('token 驗證失敗'),
            reason: 'token_invalid',
        });
        return
    }

};