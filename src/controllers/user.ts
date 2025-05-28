import { RequestHandler  } from 'express'; //驗證型別
import { StatusCodes } from 'http-status-codes' //回傳 HTTP 狀態碼
import User from '../models/user' //定義的 Mongoose 模型
import mongoose from 'mongoose'; //辨識 ValidationError 等資料錯誤
import jwt from 'jsonwebtoken'; //建立登入的 token
import bcrypt from 'bcryptjs'; //加密驗證
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
export const create: RequestHandler = async (req, res) => {
    console.log('收到的 req.body:', req.body);
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.status(400).json({
            success: false,
            message: '欄位驗證錯誤',
            errors: errors.array(),
        });
        return
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
            return;
        } else if (isMongoServerError(err)) {
            res.status(StatusCodes.CONFLICT).json({
                success: false,
                message: 'account_already_exists',
            });
            return;
        }

        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: 'unknown_error',
        });
    }
};

// 登入
export const login: RequestHandler = async (req, res)=> {
    try {
        const { account, password } = req.body;

        const user = await User.findOne({ account });
        if (!user) {
            res.status(401).json({ success: false, message: '帳號不存在' });
            return;
        }

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            res.status(401).json({ success: false, message: '密碼錯誤' });
            return;
        }

        const token = jwt.sign(
            { id: user._id, account: user.account, role: user.role },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '10s' }
        );

        res.json({
            success: true,
            message: '登入成功',
            token,
            user: { account: user.account, role: user.role },
        });

        const roleLabel = user.role === UserRole.ADMIN ? '管理員' :
                          user.role === UserRole.USER ? '一般會員' : '未知角色';
        console.log(`✅ 使用者登入：帳號=${user.account}，身分=${roleLabel}`);

    } catch (err) {
        console.error('❌ 登入發生錯誤:', err);
        res.status(500).json({ success: false, message: '伺服器錯誤' });
    }
};