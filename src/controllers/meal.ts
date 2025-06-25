import { Request, Response } from 'express';
import { MealPeriodPreset } from '../models/MealPeriodPreset';

export const getAllMealPeriodPresets = async (req: Request, res: Response) => {
    const meal = req.query.meal as string;

    try {
        if (meal) {
            const preset = await MealPeriodPreset.findOne({ meal });
            if (!preset) {
                res.status(404).json({ success: false, message: '找不到該時段的餐點' });
                return;
            }
            res.json({ success: true, data: preset });
            return;
        }

        // 沒有 meal → 回傳全部
        const presets = await MealPeriodPreset.find();
        res.json({ success: true, data: presets });
    } catch (err) {
        console.error('查詢餐點錯誤：', err);
        res.status(500).json({ success: false, message: '伺服器錯誤' });
    }
};

