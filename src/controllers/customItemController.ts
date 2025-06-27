import { Request, Response } from 'express';
import User from '../models/user';
import { MealPeriodPreset } from '../models/MealPeriodPreset';

export const resetCustomItems = async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const { type, label } = req.body ?? {};

    if (!userId) {
        res.status(401).json({ success: false, message: '未登入' });
        return;
    }

    if (!type || !['cuisine', 'meal'].includes(type)) {
        res.status(400).json({ success: false, message: 'type 必須為 "cuisine" 或 "meal"' });
        return;
    }

    if (type === 'meal' && (!label || typeof label !== 'string')) {
        res.status(400).json({ success: false, message: 'type 為 meal 時，label 為必填' });
        return
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, message: '找不到使用者' });
            return;
        }

        if (type === 'cuisine') {
            // 料理 → 清空整個 Map（完全重設）
            user.customItemsByCuisine = new Map();
        } else {
            // 餐別 → 重設指定 label 為預設值
            const preset = await MealPeriodPreset.findOne({ label });
            if (!preset) {
                res.status(404).json({ success: false, message: `找不到預設餐別分類：${label}` });
                return;
            }
            if (!user.customItemsByMeal) {
                user.customItemsByMeal = new Map();
            }
            user.customItemsByMeal.set(label, preset.items);
        }

        await user.save();

        res.json({
            success: true,
            type,
            label,
            message: type === 'cuisine'
                ? '已清空所有料理分類'
                : `已重設餐別「${label}」為預設項目`,
        });
    } catch (err) {
        console.error('[resetCustomItems] 發生錯誤', err);
        res.status(500).json({ success: false, message: '伺服器錯誤' });
    }
};
