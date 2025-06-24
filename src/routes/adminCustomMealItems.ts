import { Router } from 'express';
import User from '../models/user';
import { adminMiddleware } from '../middleware/adminMiddleware';
import { MealPeriodPreset } from '../models/MealPeriodPreset';

const router = Router();

// 匯入 customItemsByMeal 預設資料（從 MealPeriodPreset 資料表取得）
router.post('/custom-meal-items', adminMiddleware, async (req, res) => {
    try {
        // ✅ 從資料庫取得所有預設餐點資料
        const presets = await MealPeriodPreset.find();

        if (!presets.length) {
            res.status(400).json({ success: false, message: '尚未建立任何預設資料' });
            return;
        }

        // ✅ 找出所有使用者
        const users = await User.find();

        for (const user of users) {
            for (const { meal, items } of presets) {
                user.customItemsByMeal.set(meal, [...items]); // 覆蓋使用者的資料
            }
            await user.save();
        }

        res.json({
            success: true,
            message: '已成功將 MealPeriodPreset 匯入所有使用者的 customItemsByMeal',
        });
    } catch (err) {
        console.error('[POST /admin/custom-meal-items] 錯誤:', err);
        res.status(500).json({ success: false, message: '伺服器錯誤，匯入失敗' });
    }
});

// 🔐 管理員建立「時段餐點預設」
router.post('/meal-period-presets', adminMiddleware, async (req, res) => {
    const data = req.body;

    if (!Array.isArray(data) || data.some(entry => !entry.meal || !Array.isArray(entry.items))) {
        res.status(400).json({
            success: false,
            message: '格式錯誤，請提供 meal 與 items 陣列',
        });
        return;
    }

    try {
        await MealPeriodPreset.deleteMany(); // 清空舊資料
        const inserted = await MealPeriodPreset.insertMany(data);
        res.json({ success: true, message: '時段餐點預設已建立', data: inserted });
    } catch (err) {
        console.error('[POST /admin/meal-period-presets] 錯誤:', err);
        res.status(500).json({ success: false, message: '儲存失敗' });
    }
});

export default router;
