import { Request, Response } from 'express';
import Dish from '../models/Dish';
import { StatusCodes } from 'http-status-codes';

export const getDishes = async (req: Request, res: Response) => {
    try {
        const { category } = req.query;
        const query: any = {};
        
        if (category) {
            // 同時檢查 zh 與 en 分類
            query.$or = [
                { 'category.zh': category },
                { 'category.en': category }
            ];
        }

        console.log('🔍 [getDishes] 查詢條件:', query);
        const dishes = await Dish.find(query);
        console.log(`✅ [getDishes] 找到 ${dishes.length} 筆菜品`);

        const lang = (req.language || 'zh') as 'zh' | 'en';

        // 根據語系回傳對應的名稱與分類
        const translatedDishes = dishes.map(dish => {
            const dishObj = dish.toObject();
            return {
                ...dishObj,
                name: dish.name[lang] || dish.name.zh, // 優先返回對應語系，若無則回傳中文
                category: dish.category[lang] || dish.category.zh
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
        const lang = (req.language || 'zh') as 'zh' | 'en';
        
        // 從 Mongoose Schema 的 enum 中取得分類定義
        const zhCategories = (Dish.schema.path('category.zh') as any).options.enum;
        const enCategories = (Dish.schema.path('category.en') as any).options.enum;

        // 合併為物件陣列，包含 key (用於查詢) 與 label (用於顯示)
        const categories = zhCategories.map((zh: string, index: number) => ({
            zh: zh,
            en: enCategories[index] || 'Other',
        }));

        // 回傳對應語系的分類列表
        const translatedCategories = categories.map((cat: any) => ({
            key: cat[lang] || cat.zh,
            label: cat[lang] || cat.zh
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
