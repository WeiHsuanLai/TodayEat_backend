import { Request, Response } from 'express'; // 顯式指定 req, res 型別
import { StatusCodes } from 'http-status-codes';
import User from '../models/user';
import mongoose from 'mongoose';
import jwt, { JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { validationResult } from 'express-validator';
import UserRole from '../enums/UserRole';

// 檢查帳號重複
function isMongoServerError(error: unknown): error is { name: string; code: number } {
    return typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        'code' in error &&
        (error as Record<string, unknown>).name === 'MongoServerError' &&
        (error as Record<string, unknown>).code === 11000;
}

// 建立帳號
export const create = async (req: Request, res: Response) => {
    console.log('收到的 req.body:', req.body);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        res.status(400).json({
            success: false,
            message: '欄位驗證錯誤',
            errors: errors.array(),
        });
        return;
    }

    if (req.body.password.length > 20) {
        res.status(400).json({
            success: false,
            message: '密碼長度不能超過 20 字元',
        });
        return;
    }

    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = await User.create({
            account: req.body.account,
            password: hashedPassword,
            role: req.body.role,
        });

        console.log('✅ 新使用者已建立:', newUser);

        res.status(StatusCodes.OK).json({
            success: true,
            message: 'register_success',
        });
    } catch (err) {
        if (err instanceof mongoose.Error.ValidationError) {
            res.status(StatusCodes.BAD_REQUEST).json({
                success: false,
                message: 'validation_error',
            });
        } else if (isMongoServerError(err)) {
            res.status(StatusCodes.CONFLICT).json({
                success: false,
                message: 'account_already_exists',
            });
        } else {
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
                success: false,
                message: 'unknown_error',
            });
        }
    }
};

// 登入
export const login = async (req: Request, res: Response) => {
    try {
        const { account, password } = req.body;

        const user = await User.findOne({ account });
        if (!user) {
            res.status(401).json({ success: false, message: '帳號不存在' });
            return;
        }

        // ✅ 清除已過期的 token
        const now = Math.floor(Date.now() / 1000);
        user.tokens = user.tokens.filter(tokenStr => {
            try {
                const decoded = jwt.verify(tokenStr, process.env.JWT_SECRET || 'secret') as JwtPayload;
                return decoded.exp !== undefined && decoded.exp > now;
            } catch {
                return false;
            }
        });

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            res.status(401).json({ success: false, message: '密碼錯誤' });
            return;
        }

        const token = jwt.sign(
            { id: user._id, account: user.account, role: user.role },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '8h' }
        );

        if (!Array.isArray(user.tokens)) {
            user.tokens = [];
        }

        if (user.tokens.length >= 5) {
            user.tokens.shift(); // 保留最新 5 筆 token
        }

        user.tokens.push(token);
        await user.save();

        res.json({
            success: true,
            message: '登入成功',
            token,
            user: { account: user.account, role: user.role },
        });

        const roleLabel = user.role === UserRole.ADMIN ? '管理員' :
                          user.role === UserRole.USER ? '一般會員' : '未知角色';
        console.log(`✅ 使用者登入：帳號=${user.account}，身分=${roleLabel}，JWT Token = ${token}`);
    } catch (err) {
        console.error('❌ 登入發生錯誤:', err);
        res.status(500).json({ success: false, message: '伺服器錯誤' });
    }
};

// 登出
export const logout = async (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token || !req.user) {
        res.status(400).json({ success: false, message: '無效的請求' });
        return;
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            res.status(404).json({ success: false, message: '找不到使用者' });
            return;
        }

        const beforeCount = user.tokens.length;
        user.tokens = user.tokens.filter(t => t !== token);
        await user.save();

        const removed = beforeCount - user.tokens.length;
        res.json({
            success: true,
            message: removed ? '已登出' : 'Token 已不存在（可能已被移除）'
        });
    } catch (err) {
        console.error('🔴 登出錯誤:', err);
        res.status(500).json({ success: false, message: '登出失敗' });
    }
};
