import { Request, Response } from 'express';
import { InferSchemaType } from 'mongoose';
import FoodDrawRecord, { FoodDrawRecordSchema } from '../models/FoodDrawRecord';
import { DecodedUser } from '../middleware/auth';

type FoodDraw = InferSchemaType<typeof FoodDrawRecordSchema>;

// 🧩 自訂 Request 介面，包含已驗證的 userId 與 body 泛型
export interface RequestWithUser<T = unknown> extends Request {
    user?: DecodedUser;
    body: T;
}

interface DrawFoodInput {
    meal: FoodDraw['meal'];
    food: FoodDraw['food'];
}

// 日期字串格式：'YYYY-MM-DD'
const getTodayString = () => new Date().toISOString().slice(0, 10);

// 🍱 抽餐 API（每餐只保留一筆，重複會更新）
export const drawFood = async (req: RequestWithUser<DrawFoodInput>, res: Response) => {
    if (!req.user) {
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;
    const { meal, food } = req.body;
    const date = getTodayString();

    try {
        const newRecord = new FoodDrawRecord({
            userId: id,
            date,
            meal,
            food
        });

        await newRecord.save();
        res.json({ message: '抽餐成功', data: newRecord });
    } catch (error) {
        console.error('❌ drawFood error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

export const getTodayFoodDraws = async (req: RequestWithUser, res: Response) => {
    if (!req.user) {
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;
    const date = getTodayString();

    try {
        const records = await FoodDrawRecord.find({ userId: id, date }).sort({ createdAt: -1 });
        if (records.length === 0) {
            res.json({ date, meals: {} });
            return
        }
        const result: Record<string, string> = {};
        records.forEach(r => {
            result[r.meal] = r.food;
        });

        res.json({ date, meals: result });
    } catch (error) {
        console.error('❌ getTodayFoodDraws error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};


export const getAllFoodDraws = async (req: RequestWithUser, res: Response) => {
    if (!req.user) {
        res.status(401).json({ message: '未登入' });
        return;
    }

    const { id } = req.user;

    try {
        const records = await FoodDrawRecord.find({ userId: id }).sort({ createdAt: -1 });
        res.json({ count: records.length, records });
    } catch (error) {
        console.error('❌ getAllFoodDraws error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

// 📅 查某日餐點紀錄
export const getFoodDrawsByDate = async (req: RequestWithUser, res: Response) => {
    if (!req.user) {
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
        const records = await FoodDrawRecord.find({ userId: id, date }).sort({ createdAt: -1 });
        res.json(records);
    } catch (error) {
        console.error('❌ getFoodDrawsByDate error:', error);
        res.status(500).json({ message: '伺服器錯誤', error: String(error) });
    }
};

