import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import FoodRecord from '../models/FoodRecord';
import Dish from '../models/Dish';

/**
 * 儲存會員抽取的項目
 */
export const createRecord = async (req: Request, res: Response) => {
    try {
        const { dishName, note } = req.body;
        const userId = req.user?.id;

        if (!userId) {
            res.status(StatusCodes.UNAUTHORIZED).json({
                success: false,
                message: req.t('未授權'),
            });
            return;
        }

        if (!dishName) {
            res.status(StatusCodes.BAD_REQUEST).json({
                success: false,
                message: req.t('缺少菜品名稱'),
            });
            return;
        }

        let nameObj = { zh: '', en: '' };
        let dishId = null;

        // 如果傳入的是物件格式 (前端已更新)
        if (typeof dishName === 'object' && dishName.zh && dishName.en) {
            nameObj = dishName;
        } else {
            // 如果傳入的是字串 (傳統方式)，嘗試在資料庫中尋找該菜品
            const trimmedName = String(dishName).trim();
            const dish = await Dish.findOne({
                $or: [
                    { 'name.zh': trimmedName },
                    { 'name.en': trimmedName }
                ]
            });

            if (dish) {
                nameObj = dish.name;
                dishId = dish._id;
            } else {
                // 自訂項目，中英文暫時相同
                nameObj = { zh: trimmedName, en: trimmedName };
            }
        }

        const recordData = {
            userId,
            dishId,
            dishName: nameObj,
            note: note || '',
        };

        const newRecord = await FoodRecord.create(recordData);

        res.status(StatusCodes.CREATED).json({
            success: true,
            message: req.t('已成功儲存抽取項目'),
            result: newRecord,
        });
    } catch (err) {
        console.error('儲存抽取項目失敗:', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: req.t('伺服器錯誤'),
        });
    }
};

/**
 * 獲取目前登入會員的抽取歷史紀錄 (按日期分組且支援多語系)
 */
export const getMyRecords = async (req: Request, res: Response) => {
    try {
        const userId = req.user?.id;
        const lang = (req.language || 'zh') as 'zh' | 'en';

        if (!userId) {
            res.status(StatusCodes.UNAUTHORIZED).json({
                success: false,
                message: req.t('未授權'),
            });
            return;
        }

        const records = await FoodRecord.find({ userId }).sort({ createdAt: -1 });

        const groupedRecords = records.reduce((acc: any, record: any) => {
            const date = new Date(record.createdAt).toISOString().split('T')[0];
            if (!acc[date]) {
                acc[date] = [];
            }

            const recordObj = record.toObject();
            
            // 返回對應語系的菜品名稱
            recordObj.dishName = record.dishName[lang] || record.dishName.zh;
            
            acc[date].push(recordObj);
            return acc;
        }, {});

        res.status(StatusCodes.OK).json({
            success: true,
            result: groupedRecords,
        });
    } catch (err) {
        console.error('獲取抽取歷史失敗:', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: req.t('伺服器錯誤'),
        });
    }
};

/**
 * 修改單筆抽取紀錄
 */
export const updateRecord = async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const { dishName, note } = req.body;
        const userId = req.user?.id;

        const record = await FoodRecord.findOne({ _id: id, userId });

        if (!record) {
            res.status(StatusCodes.NOT_FOUND).json({
                success: false,
                message: req.t('找不到該紀錄或無權限修改'),
            });
            return;
        }

        if (dishName !== undefined) {
            if (typeof dishName === 'object' && dishName.zh && dishName.en) {
                record.dishName = dishName;
            } else {
                const trimmedName = String(dishName).trim();
                record.dishName = { zh: trimmedName, en: trimmedName };
            }
        }
        if (note !== undefined) record.note = note;

        await record.save();

        res.status(StatusCodes.OK).json({
            success: true,
            message: req.t('紀錄已成功更新'),
            result: record,
        });
    } catch (err) {
        console.error('更新紀錄失敗:', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: req.t('伺服器錯誤'),
        });
    }
};

/**
 * 刪除單筆抽取紀錄
 */
export const deleteRecord = async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        const userId = req.user?.id;

        const record = await FoodRecord.findOneAndDelete({ _id: id, userId });

        if (!record) {
            res.status(StatusCodes.NOT_FOUND).json({
                success: false,
                message: req.t('找不到該紀錄或無權限刪除'),
            });
            return;
        }

        res.status(StatusCodes.OK).json({
            success: true,
            message: req.t('紀錄已刪除'),
        });
    } catch (err) {
        console.error('刪除紀錄失敗:', err);
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: req.t('伺服器錯誤'),
        });
    }
};
