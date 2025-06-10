import express from 'express';
import { register, logout,forgotPassword,changePassword,login } from '../controllers/user';
import { body } from 'express-validator';
import { authMiddleware } from '../middleware/auth';
import { getLoginLogs } from '../controllers/getLoginLogs';

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
    register
);

router.post('/login', login);

// 查詢登入紀錄
router.get('/login-logs', authMiddleware, getLoginLogs);
router.post('/logout', authMiddleware, logout);

router.get('/', (req, res) => {
    res.send('Hello from user route');
});

// 修改密碼
router.post('/change-password', authMiddleware, changePassword);

// 寄送郵件(目前)
router.post('/forgot-password', forgotPassword);

export default router; 
