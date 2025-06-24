import { Request, Response } from 'express';
import User from '../models/user';
import { Prize } from '../models/Prize';

export const resetCustomItems = async (req: Request, res: Response) => {
    const userId = req.user?.id;

    if (!userId) {
        res.status(401).json({ success: false, message: req.t('未登入') });
        return;
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            res.status(404).json({ success: false, message: req.t('找不到使用者') });
            return;
        }

        const defaultPrizes = await Prize.find();
        if (!defaultPrizes.length) {
            res.status(500).json({ success: false, message: req.t('沒有預設料理資料') });
            return;
        }

        const customItemsMap = new Map<string, string[]>();
        for (const prize of defaultPrizes) {
            customItemsMap.set(prize.label, [...prize.items]);
        }

        user.customItemsByCuisine = customItemsMap;
        await user.save();

        res.json({ success: true, message: req.t('已重置為預設料理'), customItems: user.customItemsByCuisine });
    } catch (err) {
        console.error('[resetCustomItems] 發生錯誤', err);
        res.status(500).json({ success: false, message: req.t('重置失敗') });
    }
};
