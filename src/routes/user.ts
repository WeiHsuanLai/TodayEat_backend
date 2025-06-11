import express from 'express';
import { register, logout,forgotPassword,changePassword,login,deleteAccount } from '../controllers/user';
import { body } from 'express-validator';
import { authMiddleware } from '../middleware/auth';
import { getLoginLogs } from '../controllers/getLoginLogs';

const router = express.Router();


// ✅ 公開 API

// 註冊
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

// 登入
router.post('/login', login);

// 寄送郵件(目前)
router.post('/forgot-password', forgotPassword);

// 測試
router.get('/', (req, res) => {
    res.send('Hello from user route');
});


// ✅ 需要登入驗證的 API

// 登出
router.post('/logout', authMiddleware, logout);

// 查詢登入紀錄
router.get('/login-logs', authMiddleware, getLoginLogs);

// 修改密碼
router.post('/change-password', authMiddleware, changePassword);

// 註銷帳號
router.delete('/delete', authMiddleware, deleteAccount); 


export default router; 
