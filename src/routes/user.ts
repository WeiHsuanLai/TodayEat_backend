import express from 'express';
import { 
    register,
    logout,
    forgotPassword,
    changePassword,
    login,
    deleteAccount,
    getCurrentUser,
    getCustomItems,
    addCustomItem,
    deleteCustomItems,
    addCustomLabel,
    deleteCustomLabels
} from '../controllers/user';
import { body } from 'express-validator';
import { authMiddleware } from '../middleware/auth';
import { getLoginLogs } from '../controllers/getLoginLogs';
import { resetCustomItems } from '../controllers/customItemController';

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

// 檢查token 是否過期
router.get('/getCurrentUser', authMiddleware, getCurrentUser);

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

// 取得使用者自訂項目(全部各式料理)
router.get('/custom-items', authMiddleware, getCustomItems);

// 新增使用者自訂項目
router.post('/custom-items', authMiddleware, addCustomItem);

// 刪除使用者自訂料理項目
router.delete('/custom-items/label', authMiddleware, deleteCustomLabels);

// 刪除使用者自訂單一料理
router.delete('/custom-items', authMiddleware, deleteCustomItems);

// 新增料理種類
router.post('/custom-items/label', authMiddleware, addCustomLabel);

// 重置所有料理
router.post('/custom-items/reset', authMiddleware, resetCustomItems);

export default router; 
