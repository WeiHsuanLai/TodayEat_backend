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

        const dishes = await Dish.find(query);

        res.status(StatusCodes.OK).json({
            success: true,
            data: dishes,
        });
    } catch (err) {
        console.error('❌ 取得菜品失敗', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: '伺服器錯誤，無法取得菜品',
        });
    }
};

export const getCategories = async (req: Request, res: Response) => {
    try {
        // 從 Mongoose Schema 的 enum 中取得分類定義
        const categories = Dish.schema.path('category').options.enum;

        res.status(StatusCodes.OK).json({
            success: true,
            data: categories,
        });
    } catch (err) {
        console.error('❌ 取得分類失敗', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: '伺服器錯誤，無法取得分類',
        });
    }
};
