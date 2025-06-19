import { Router } from 'express';
import { Prize } from '../models/Prize';

const router = Router();

// 取得所有獎項
router.get('/', async (req, res) => {
    try {
        const prizes = await Prize.find().lean();
        res.json(prizes);
    } catch (err) {
        console.error('[GET /prizes]', err);
        res.status(500).json({ error: '無法取得料理清單' });
    }
});

// 新增一個獎項（可選功能）
router.post('/', async (req, res) => {
    const data = req.body;

    // 如果是多筆陣列
    if (Array.isArray(data)) {
        const invalid = data.some((entry) => !entry.label || !Array.isArray(entry.items));
        if (invalid) {
            res.status(400).json({ error: '每筆資料都需要有 label 與 items 陣列' });
            return;
        }
        try {
            const inserted = await Prize.insertMany(data);
            res.status(201).json(inserted);
            return;
        } catch (err) {
            console.error('[POST /prizes] 批次失敗', err);
            res.status(500).json({ error: '批次儲存失敗' });
            return;
        }
    }

    // 如果是單筆物件
    const { label, items, imageUrl, mealTimes } = data;
    if (!label || !Array.isArray(items)) {
        res.status(400).json({ error: 'label 與 items 為必填欄位' });
        return;
    }

    try {
        const newPrize = await Prize.create({ label, items, imageUrl, mealTimes });
        res.status(201).json(newPrize);
        return;
    } catch (err) {
        console.error('[POST /prizes] 單筆失敗', err);
        res.status(500).json({ error: '儲存失敗' });
        return;
    }
});


export default router;
