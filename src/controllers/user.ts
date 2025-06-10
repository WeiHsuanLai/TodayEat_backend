import { Request, Response } from 'express'; // 顯式指定 req, res 型別
import { StatusCodes } from 'http-status-codes'; // HTTP 狀態碼
import User from '../models/user'; // Mongoose 資料模型
import mongoose from 'mongoose';
import jwt, { JwtPayload } from 'jsonwebtoken'; // 產生與解析 JWT
import bcrypt from 'bcryptjs'; //密碼雜湊與驗證
import { validationResult } from 'express-validator'; // 驗證欄位
import UserRole from '../enums/UserRole'; // 使用者權限定義
import { formatUnixTimestamp } from '../utils/formatTime'; // 時間轉換工具

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
export const register = async (req: Request, res: Response) => {
    log('收到的 req.body:', req.body);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        res.status(400).json({
            success: false,
            message: req.t('欄位驗證錯誤'),
            errors: errors.array(),
        });
        return;
    }

    if (req.body.password.length > 20) {
        res.status(400).json({
            success: false,
            message: req.t('密碼長度不能超過 20 字元'),
        });
        return;
    }

    // 禁用 api 來註冊管理員帳號
    const rawRole = req.body.role;
    const role = rawRole !== undefined ? Number(rawRole) : UserRole.USER;
    if (role === UserRole.ADMIN) {
        res.status(403).json({
            success: false,
            message: req.t('禁止註冊管理員帳號'),
        });
        return;
    }

    // 檢查帳號是否重複
    const existingAccount = await User.findOne({ account: req.body.account });
    if (existingAccount) {
        res.status(StatusCodes.CONFLICT).json({
            success: false,
            message: req.t('此帳號已存在'),
        });
        return;
    }

    // 檢查 email 是否已經註冊
    const existingEmail = await User.findOne({ email: req.body.email });
    if (existingEmail) {
        res.status(StatusCodes.CONFLICT).json({
            success: false,
            message: req.t('此 Email 已被註冊'),
        });
        return;
    }

    try {
        // 建立帳號
        const newUser = await User.create({
            account: req.body.account,
            password: req.body.password,
            email: req.body.email,
            role,
        });

        // 建立 JWT token
        const token = jwt.sign(
            { id: newUser._id, account: newUser.account, role: newUser.role },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '8h' }
        );

        // 存入 token 清單
        newUser.tokens = [token];
        await newUser.save();

        const decoded = jwt.decode(token) as JwtPayload;
        const iatFormatted = formatUnixTimestamp(decoded.iat);
        const expFormatted = formatUnixTimestamp(decoded.exp);

        log('✅ 新使用者已建立並自動登入:', newUser);

        res.status(StatusCodes.OK).json({
            success: true,
            message: req.t('註冊成功'),
            token,
            iat: iatFormatted,
            exp: expFormatted,
            user: {
                account: newUser.account,
                email: newUser.email,
                role: newUser.role,
            },
        });
    } catch (err) {
        if (err instanceof mongoose.Error.ValidationError) {
            res.status(StatusCodes.BAD_REQUEST).json({
                success: false,
                message: req.t('欄位驗證錯誤'),
            });
        } else if (isMongoServerError(err)) {
            res.status(StatusCodes.CONFLICT).json({
                success: false,
                message: req.t('此帳號已存在'),
            });
        } else {
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
                success: false,
                message: req.t('註冊失敗，請稍後再試'),
            });
        }
    }
};

// 登入
export const login = async (req: Request, res: Response) => {
    try {
        // 比對帳號
        const { account, password } = req.body;
        const user = await User.findOne({ account });
        if (!user) {
            res.status(401).json({ success: false, message: req.t('帳號不存在') });
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

        // 比對密碼轉換
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            res.status(401).json({ success: false, message: req.t('密碼錯誤') });
            return;
        }

        // 建立token
        const token = jwt.sign(
            { id: user._id, account: user.account, role: user.role },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '8h' }
        );

        user.tokens = [token];

        await user.save();

        const decoded = jwt.decode(token) as JwtPayload;
        const iatFormatted = formatUnixTimestamp(decoded.iat);
        const expFormatted = formatUnixTimestamp(decoded.exp);

        res.json({
            success: true,
            message: req.t('登入成功'),
            token,
            iat: iatFormatted,
            exp: expFormatted,
            user: { account: user.account, role: user.role },
        });

        const roleLabel = 
            user.role === UserRole.ADMIN ? '管理員' :
            user.role === UserRole.USER ? '一般會員' : '未知角色';
        log(`✅ 使用者登入：帳號=${user.account}，身分=${roleLabel}`);
    } catch (err) {
        logError('❌ 登入發生錯誤:', err);
        res.status(500).json({ success: false, message: req.t('伺服器錯誤') });
    }
};

// 登出
export const logout = async (req: Request, res: Response) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token || !req.user) {
        res.status(400).json({ success: false, message: req.t('無效的請求') });
        return;
    }

    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            res.status(404).json({ success: false, message: req.t('找不到使用者') });
            return;
        }

        const beforeCount = user.tokens.length;
        user.tokens = user.tokens.filter(t => t !== token);
        await user.save();

        const removed = beforeCount - user.tokens.length;

        if (removed) {
            log(`👋 使用者登出：帳號=${user.account}`);
        } else {
            log(`ℹ️ Token 已不存在（可能早已移除）：帳號=${user.account}`);
        }

        res.json({
            success: true,
            message: removed ? req.t('已登出') : req.t('Token 已不存在（可能已被移除）')
        });
    } catch (err) {
        logError('🔴 登出錯誤:', err);
        res.status(500).json({ success: false, message: req.t('登出失敗') });
    }
};
