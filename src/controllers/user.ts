import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes'
import User from '../models/user'
import mongoose from 'mongoose';

// 檢查帳號重複
function isMongoServerError(error: unknown): error is { name: string; code: number } {
    return typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        'code' in error &&
        (error as Record<string, unknown>).name === 'MongoServerError' &&
        (error as Record<string, unknown>).code === 11000;
}

// 接收使用者傳入資料
export const create = async (req: Request, res: Response): Promise<void> => {
    // 若新增成功回傳 JSON
    try {
        await User.create(req.body)
        res.status(StatusCodes.OK).json({
            success: true,
            message: 'register_success'
        })
    } catch (err) {
        // 資料驗證錯誤
        if (err instanceof mongoose.Error.ValidationError) {
            res.status(StatusCodes.BAD_REQUEST).json({
                success: false,
                message: 'validation_error'
            });
            return;
        } 
        // 帳號重複
        else if (isMongoServerError(err)) {
            res.status(StatusCodes.CONFLICT).json({
                success: false,
                message: 'account_already_exists'
            });
            return;
        }
        // 未知錯誤
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
            success: false,
            message: 'unknown_error'
        });
    }
}