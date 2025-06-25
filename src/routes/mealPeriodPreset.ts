import { Router } from 'express';
import { MealPeriodPreset } from '../models/MealPeriodPreset';
import { adminMiddleware } from '../middleware/adminMiddleware';

const router = Router();

// 取得所有時段分類
router.get('/', async (req, res) => {
    try {
        const mealPresets = await MealPeriodPreset.find().lean();
        res.json(mealPresets);
    } catch (err) {
        console.error('[GET /mealPresets]', err);
        res.status(500).json({ error: '無法取得時段分類清單' });
    }
});

// 匯入預設資料（可選功能）
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
            const inserted = await MealPeriodPreset.insertMany(data);
            res.status(201).json(inserted);
            return;
        } catch (err) {
            console.error('[POST /mealPresets] 批次失敗', err);
            res.status(500).json({ error: '批次儲存失敗' });
            return;
        }
    }

    // 如果是單筆物件
    const { label, items } = data;
    const exists = await MealPeriodPreset.findOne({ label });
    if (exists) {
        res.status(409).json({ error: '分類已存在' });
        return;
    }
    if (!label || !Array.isArray(items)) {
        res.status(400).json({ error: 'label 與 items 為必填欄位' });
        return;
    }

    try {
        const newPreset = await MealPeriodPreset.create({ label, items });
        res.status(201).json(newPreset);
        return;
    } catch (err) {
        console.error('[POST /mealPresets] 單筆失敗', err);
        res.status(500).json({ error: '儲存失敗' });
        return;
    }
});

export default router;
