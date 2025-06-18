import { Request, Response } from 'express'; // 顯式指定 req, res 型別
import { StatusCodes } from 'http-status-codes'; // HTTP 狀態碼
import User from '../models/user'; // Mongoose 資料模型
import mongoose from 'mongoose';
import jwt, { JwtPayload } from 'jsonwebtoken'; // 產生與解析 JWT
import bcrypt from 'bcryptjs'; //密碼雜湊與驗證
import { validationResult } from 'express-validator'; // 驗證欄位
import UserRole from '../enums/UserRole'; // 使用者權限定義
import { formatUnixTimestamp } from '../utils/formatTime'; // 時間轉換工具
import { sendResetPasswordEmail } from '../utils/mailer'; // 傳送 emaal
import  LoginLog  from '../models/LoginLog'; // 查詢登入登出紀錄
import { log } from 'console';

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
    log("errors",errors)
    if (!errors.isEmpty()) {
        const formattedErrors = errors.array().map((err) => ({
            msg: err.msg,
        }));

        res.status(400).json({
            success: false,
            message: req.t('欄位驗證錯誤'),
            errors: formattedErrors,
        });
        log('❌ 欄位驗證錯誤', formattedErrors);
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
            { 
                id: newUser._id, 
                account: newUser.account, 
                role: newUser.role,
                avatar: newUser.avatar || '', },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '8h' }
        );

        // 存入 token 清單
        newUser.tokens = [token];
        newUser.lastLoginAt = new Date();
        await newUser.save();

        // const decoded = jwt.decode(token) as JwtPayload;
        // const iatFormatted = formatUnixTimestamp(decoded.iat);
        // const expFormatted = formatUnixTimestamp(decoded.exp);

        log('✅ 新使用者已建立並自動登入:', newUser);

        res.status(StatusCodes.OK).json({
            success: true,
            message: req.t('註冊成功'),
            token,
            // iat: iatFormatted,
            // exp: expFormatted,
            user: {
                account: newUser.account,
                // email: newUser.email,
                role: newUser.role,
            },
        });

        await LoginLog.create({
            userId: newUser._id,
            action: 'login',
            ip: req.ip,
            userAgent: req.headers['user-agent'] || 'unknown',
        });
        
    } catch (err) {
        if (err instanceof mongoose.Error.ValidationError) {
            const mongooseErrors = Object.entries(err.errors).map(([key, val]) => ({
                field: key,
                msg: (val as mongoose.Error.ValidatorError).message,
            }));
        
            res.status(StatusCodes.BAD_REQUEST).json({
                success: false,
                message: mongooseErrors[0].msg,
            });
            log("欄位驗證錯誤", mongooseErrors);
        } else if (isMongoServerError(err)) {
            res.status(StatusCodes.CONFLICT).json({
                success: false,
                message: req.t('此帳號已存在'),
            });
            log("此帳號已存在");
        } else {
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
                success: false,
                message: req.t('註冊失敗，請稍後再試'),
            });
            log("註冊失敗，請稍後再試");
        }
    }
};

// 註銷帳號
export const deleteAccount = async (req: Request, res: Response) => {
    try {
        const userId = req.user?.id;

        const user = await User.findById(userId);
        const result = await User.findByIdAndUpdate(userId, {
            isDeleted: true,
            deletedAt: new Date(),
            originalAccount: user?.account,
            originalEmail: user?.email,
            email: `deleted_${Date.now()}@example.com`,
            account: `deleted_user_${userId}`,
            tokens: [],
            cart: [],
        });

        if (!result) {
            res.status(404).json({ message: '找不到使用者' });
            return
        }

        res.status(200).json({ message: '帳號已成功註銷' });
    } catch (err) {
        console.error('註銷帳號失敗', err);
        res.status(500).json({ message: '伺服器錯誤，無法註銷帳號' });
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
            log("帳號不存在");
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
            log("密碼錯誤");
            return;
        }

        // 建立token
        const token = jwt.sign(
            { 
                id: user._id, 
                account: user.account, 
                role: user.role,
                avatar: user.avatar || '',
            },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '8h' }
        );

        user.tokens = [token];
        user.lastLoginAt = new Date();
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
            user: { 
                account: user.account, 
                role: user.role, 
                avatar: user.avatar || '',
                token: req.headers.authorization?.split(' ')[1],
            },
        });

        await LoginLog.create({
            userId: user._id,
            action: 'login',
            ip: req.ip,
            userAgent: req.headers['user-agent'] || 'unknown',
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

// 檢查 token 是否過期
export const getCurrentUser = async (req: Request, res: Response) => {
    const user = req.user;

    if (!user) {
        res.status(401).json({
            success: false,
            message: '未授權',
        });
        return
    }

    res.json({
        success: true,
        user: {
            username: user.account,
            role: user.role,
            avatar: user.avatar || '',
            token: req.headers.authorization?.split(' ')[1],
        },
    });
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

        user.tokens = user.tokens.filter(t => t !== token);
        user.lastLogoutAt = new Date();
        await user.save();

        await LoginLog.create({
            userId: user._id,
            action: 'logout',
            ip: req.ip,
            userAgent: req.headers['user-agent'] || 'unknown',
        });

        log(`👋 使用者登出：帳號=${user.account}`);

        // 統一簡單回應格式
        res.status(200).json({
            success: true,
            message: req.t('您已成功登出'),
        });
    } catch (err) {
        logError('🔴 登出錯誤:', err);
        res.status(500).json({ success: false, message: req.t('登出失敗') });
    }
};

// 修改密碼
export const changePassword = async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const { currentPassword, newPassword } = req.body;

    if (!userId || !currentPassword || !newPassword) {
        res.status(400).json({ success: false, message: req.t('請填寫完整欄位') });
        return
    }

    const user = await User.findById(userId);
    if (!user) {
        res.status(404).json({ success: false, message: req.t('找不到使用者') });
        return
    }

    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
        res.status(401).json({ success: false, message: req.t('目前密碼錯誤') });
        return
    }

    user.password = newPassword;
    await user.save();

    res.json({ success: true, message: req.t('密碼已成功修改') });
};


//寄送郵件
export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.body;

    try {
        await sendResetPasswordEmail(email, '這是測試內容，不含 token');
        res.json({ message: '測試郵件已成功寄出' });
    } catch (err) {
        console.error('寄信失敗：', err);
        res.status(500).json({ message: '寄信失敗' });
    }
};