import { Request, Response } from 'express';
import User from '../models/user';

export const resetCustomItems = async (req: Request, res: Response) => {
    const userId = req.user?.id;
    const body = req.body ?? {};
    

    if (!req.body || typeof req.body !== 'object') {
        res.status(400).json({
            success: false,
            message: req.t?.('缺少請求內容') ?? '缺少請求內容',
        });
        return;
    }
    const { type } = body;

    if (!userId) {
        res.status(401).json({ success: false, message: '未登入' });
        return;
    }

    if (!type) {
        res.status(400).json({ success: false, message: 'type 為必填' });
        return;
    }

    if (!['cuisine', 'meal'].includes(type)) {
        res.status(400).json({ success: false, message: 'type 必須為 "cuisine" 或 "meal"' });
        return;
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, message: '找不到使用者' });
            return;
        }

        // 重置對應欄位
        if (type === 'cuisine') {
            user.customItemsByCuisine = new Map();
        } else {
            user.customItemsByMeal = new Map();
        }

        await user.save();

        res.json({
            success: true,
            message: `已重置為預設${type === 'cuisine' ? '料理' : '餐別'}`,
            type,
        });
    } catch (err) {
        logError('[resetCustomItems] 發生錯誤', {
            error: err,
            userId,
            body: req.body,
        });
    }
};

