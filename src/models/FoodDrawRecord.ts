import { Schema, model } from 'mongoose';

// 定義「每日抽餐紀錄」的資料 Schema
const FoodDrawRecordSchema = new Schema({
  // 使用者 ID，關聯 User
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },

    // 每日四餐類型
    meal: {
        type: String,
        enum: ['breakfast', 'lunch', 'dinner', 'midnight'],
        required: true
    },

    // 餐點名稱
    food: {
        type: String,
        required: true,
        trim: true // 自動清除前後空白
    },

    // 建立日期（格式：YYYY-MM-DD）
    date: {
        type: String,
        required: true,
        match: /^\d{4}-\d{2}-\d{2}$/ // 確保符合日期格式
    },

    // 最後更新時間
    updatedAt: {
        type: Date,
        default: Date.now
    },

    // 備註欄位（選填）
    note: {
        type: String,
        default: '',
        trim: true
    }
},{ versionKey: false });

// 建立複合索引：每人每日每餐只允許一筆
FoodDrawRecordSchema.index({ userId: 1, date: 1, meal: 1 }, { unique: true });

// 導出模型與 Schema（方便 TS 型別推導）
const FoodDrawRecord = model('FoodDrawRecord', FoodDrawRecordSchema);
export default FoodDrawRecord;
export { FoodDrawRecordSchema };
