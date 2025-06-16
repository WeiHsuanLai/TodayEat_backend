import { Schema, model } from 'mongoose';

// 定義「點心紀錄」Schema
const SnackRecordSchema = new Schema({
    // 使用者
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },

    // 點心名稱
    snack: { type: String, required: true },

    // 建立日期
    createdAt: { type: Date, default: Date.now }
});

export default model('SnackRecord', SnackRecordSchema);
