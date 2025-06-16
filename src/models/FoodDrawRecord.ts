import { Schema, model } from 'mongoose';

// 定義「每日抽餐紀錄」的資料 Schema
const FoodDrawRecordSchema = new Schema({

    // 使用者
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },

    // 每日四餐
    meal: {
        type: String,
        enum: ['breakfast', 'lunch', 'dinner', 'midnight'],
        required: true
    },

    // 餐點名稱
    food: { type: String, required: true },

    // 建立日期
    date: {
        type: String,
        required: true
    },

    // 最後修改時間
    updatedAt: { type: Date, default: Date.now },

    // 備註
    note: { type: String, default: '' }
});

// 建立唯一索引，保證每人每天每餐只有一筆紀錄
FoodDrawRecordSchema.index({ userId: 1, date: 1, meal: 1 }, { unique: true });

export default model('FoodDrawRecord', FoodDrawRecordSchema);
