import { Router } from 'express';
import { createRecord, getMyRecords, deleteRecord, updateRecord } from '../controllers/foodRecord';
import { authMiddleware } from '../middleware/auth';

const router = Router();

// 所有抽取紀錄相關的 API 都需要登入驗證
router.post('/', authMiddleware, createRecord); // 儲存抽取項目
router.get('/my', authMiddleware, getMyRecords); // 獲取我的抽取歷史
router.patch('/:id', authMiddleware, updateRecord); // 修改單筆紀錄 (標題或備註)
router.delete('/:id', authMiddleware, deleteRecord); // 刪除單筆紀錄

export default router;
