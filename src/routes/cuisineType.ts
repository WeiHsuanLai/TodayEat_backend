import { Router } from 'express';
import { CuisineType } from '../models/CuisineType';
import { adminMiddleware } from '../middleware/adminMiddleware';

const router = Router();

// 取得所有獎項
router.get('/', async (req, res) => {
    try {
        const cuisineTypes = await CuisineType.find().lean();
        res.json(cuisineTypes);
    } catch (err) {
        console.error('[GET /cuisineTypes]', err);
        res.status(500).json({ error: '無法取得料理清單' });
    }
});

// 新增一個獎項（可選功能）
router.post('/', adminMiddleware, async (req, res) => {
    const data = req.body;

    // 如果是多筆陣列
    if (Array.isArray(data)) {
        const invalid = data.some((entry) => !entry.label || !Array.isArray(entry.items));
        if (invalid) {
            res.status(400).json({ error: '每筆資料都需要有 label 與 items 陣列' });
            return;
        }
        try {
            const inserted = await CuisineType.insertMany(data);
            res.status(201).json(inserted);
            return;
        } catch (err) {
            console.error('[POST /cuisineTypes] 批次失敗', err);
            res.status(500).json({ error: '批次儲存失敗' });
            return;
        }
    }

    // 如果是單筆物件
    const { label, items, imageUrl } = data;
    if (!label || !Array.isArray(items)) {
        res.status(400).json({ error: 'label 與 items 為必填欄位' });
        return;
    }

    try {
        const newCuisineType = await CuisineType.create({ label, items, imageUrl });
        res.status(201).json(newCuisineType);
        return;
    } catch (err) {
        console.error('[POST /cuisineTypes] 單筆失敗', err);
        res.status(500).json({ error: '儲存失敗' });
        return;
    }
});


export default router;
