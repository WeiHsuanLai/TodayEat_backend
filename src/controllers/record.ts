import { Request, Response } from 'express';
import { InferSchemaType } from 'mongoose';
import FoodDrawRecord, { FoodDrawRecordSchema } from '../models/FoodDrawRecord';
import SnackRecord, { SnackRecordSchema } from '../models/SnackRecord';
import { DecodedUser } from '../middleware/auth';

type FoodDraw = InferSchemaType<typeof FoodDrawRecordSchema>;
type Snack = InferSchemaType<typeof SnackRecordSchema>;

// 🧩 自訂 Request 介面，包含已驗證的 userId 與 body 泛型
export interface RequestWithUser<T = unknown> extends Request {
    user?: DecodedUser;
    body: T;
}

interface DrawFoodInput {
    meal: FoodDraw['meal'];
    food: FoodDraw['food'];
}

interface AddSnackInput {
    snack: Snack['snack'];
}

// 日期字串格式：'YYYY-MM-DD'
const getTodayString = () => new Date().toISOString().slice(0, 10);

// 🍱 抽餐 API（每餐只保留一筆，重複會更新）
export const drawFood = async (req: RequestWithUser<DrawFoodInput>, res: Response) => {
    if (!req.user){
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;
    const { meal, food } = req.body;
    const date = getTodayString();

    try {
        const result = await FoodDrawRecord.findOneAndUpdate(
            { userId: id, date, meal },
            { food, updatedAt: new Date() },
            { upsert: true, new: true }
        );
        res.json({ message: '抽餐成功', data: result });
    } catch (error) {
        console.error('❌ drawFood error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

// 🍱 查今日四餐（含 null）
export const getTodayFoodDraws = async (req: RequestWithUser, res: Response) => {
    if (!req.user){
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;
    const date = getTodayString();

    try {
        const records = await FoodDrawRecord.find({ userId: id, date });
        const meals: FoodDraw['meal'][] = ['breakfast', 'lunch', 'dinner', 'midnight'];
        const result: Record<FoodDraw['meal'], string | null> = {
            breakfast: null,
            lunch: null,
            dinner: null,
            midnight: null
        };
        meals.forEach(meal => {
            result[meal] = records.find(r => r.meal === meal)?.food || null;
        });
        res.json({ date, meals: result });
    } catch (error) {
        console.error('❌ getTodayFoodDraws error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

// 📅 查某日餐點紀錄
export const getFoodDrawsByDate = async (req: RequestWithUser, res: Response) => {
    if (!req.user){
        res.status(401).json({ message: '未登入' });
        return;
    }
    const { id } = req.user;
    const { date } = req.params;

    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        res.status(400).json({ message: '日期格式錯誤，請使用 YYYY-MM-DD' });
        return;
    }

    try {
        const records = await FoodDrawRecord.find({ userId: id, date });
        res.json(records);
    } catch (error) {
        console.error('❌ getFoodDrawsByDate error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

// 🍡 新增點心紀錄
export const addSnack = async (req: RequestWithUser<AddSnackInput>, res: Response) => {
    if (!req.user){
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;
    const snack = req.body.snack?.trim();

    if (!snack) {
        res.status(400).json({ message: '點心名稱不能為空' });
        return;
    }

    try {
        const result = await SnackRecord.create({ userId: id, snack });
        res.json({ message: '點心已記錄', data: result });
    } catch (error) {
        console.error('❌ addSnack error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

// 🍭 查詢點心紀錄
export const getSnackHistory = async (req: RequestWithUser, res: Response) => {
    if (!req.user){
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;
    const limit = Math.max(1, Math.min(parseInt(req.query.limit as string) || 100, 500));

    try {
        const snacks = await SnackRecord.find({ userId: id })
            .sort({ createdAt: -1 })
            .limit(limit);
        res.json(snacks);
    } catch (error) {
        console.error('❌ getSnackHistory error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

