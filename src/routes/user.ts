import express from 'express';
import { create, logout } from '../controllers/user';
import { body } from 'express-validator';
import { login } from '../controllers/user';
import { authMiddleware } from '../middleware/auth';
import { formatUnixTimestamp } from '../utils/formatTime';
const router = express.Router();

router.post(
    '/register',
    [
        body('account')
        .isLength({ min: 4, max: 20 }).withMessage('帳號長度應為4~20')
        .isAlphanumeric().withMessage('帳號只能包含英文與數字'),
        body('password')
        .isLength({ min: 4 }).withMessage('密碼長度至少4碼'),
    ],
    create
);

router.post('/login', login);

router.post('/logout', authMiddleware, logout);

router.get('/', (req, res) => {
    res.send('Hello from user route');
});

// 測試登入失效
router.get('/me', authMiddleware, (req, res) => {
    if (!req.user) {
        res.status(401).json({ success: false, message: '尚未登入' });
        return
    }

    const { id, account, role, iat, exp } = req.user;

    res.json({
        success: true,
        message: '你已登入',
        user: {
            id,
            account,
            role,
            iat: formatUnixTimestamp(iat), // 預設使用系統本地時間
            exp: formatUnixTimestamp(exp),
        }
    });
});

export default router; 
