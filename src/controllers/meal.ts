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
            res.json({
                success: true,
                filterType: 'meal',
                title: getMealTitle(meal),
                data: preset,
            });
            return;
        }

        // 沒有 meal → 回傳全部
        const presets = await MealPeriodPreset.find();
        const dataWithTitle = presets.map(p => ({
            ...p.toObject(),
            title: getMealTitle(p.meal),
        }));
        res.json({ 
            success: true,
            filterType: 'meal',
            data: dataWithTitle 
        });
    } catch (err) {
        console.error('查詢餐點錯誤：', err);
        res.status(500).json({ success: false, message: '伺服器錯誤' });
    }
};

function getMealTitle(meal: string): string {
    switch (meal) {
        case 'breakfast': return '早餐';
        case 'lunch': return '午餐';
        case 'dinner': return '晚餐';
        case 'midnight': return '宵夜';
        default: return '未分類';
    }
}


