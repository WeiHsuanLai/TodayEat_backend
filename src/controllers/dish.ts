import { Request, Response } from 'express';
import Dish from '../models/Dish';
import { StatusCodes } from 'http-status-codes';

export const getDishes = async (req: Request, res: Response) => {
    try {
        const { category } = req.query;
        const query: any = {};
        
        if (category) {
            query.category = category;
        }

        console.log('🔍 [getDishes] 查詢條件:', query);
        const dishes = await Dish.find(query);
        console.log(`✅ [getDishes] 找到 ${dishes.length} 筆菜品`);

        const lang = (req.language || 'zh') as 'zh' | 'en';

        // 根據語系回傳對應的名稱，並使用 i18n 翻譯分類
        const translatedDishes = dishes.map(dish => {
            const dishObj = dish.toObject();
            return {
                ...dishObj,
                name: dish.name[lang] || dish.name.zh, // 優先返回對應語系，若無則回傳中文
                category: req.t(dish.category)
            };
        });

        res.status(StatusCodes.OK).json({
            success: true,
            data: translatedDishes,
        });
    } catch (err) {
        console.error('❌ 取得菜品失敗', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: req.t('伺服器錯誤，無法取得菜品'),
        });
    }
};

export const getCategories = async (req: Request, res: Response) => {
    try {
        // 從 Mongoose Schema 的 enum 中取得分類定義
        const categories = Dish.schema.path('category').options.enum;

        // 回傳翻譯後的分類列表
        const translatedCategories = categories.map((cat: string) => ({
            key: cat,
            label: req.t(cat)
        }));

        res.status(StatusCodes.OK).json({
            success: true,
            data: translatedCategories,
        });
    } catch (err) {
        console.error('❌ 取得分類失敗', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: req.t('伺服器錯誤，無法取得分類'),
        });
    }
};
