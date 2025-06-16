import { Schema, model } from 'mongoose';

// 定義「點心紀錄」Schema
const SnackRecordSchema = new Schema({
  // 使用者 ID，關聯 User 模型
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },

    // 點心名稱
    snack: {
        type: String,
        required: true,
        trim: true, // 清除前後空白
        minlength: [1, '點心名稱不得為空']
    },

    // 建立時間
    createdAt: {
        type: Date,
        default: Date.now
    }
},{ versionKey: false });

// 建議可加 index 提升查詢效能（可選）
SnackRecordSchema.index({ userId: 1, createdAt: -1 });

const SnackRecord = model('SnackRecord', SnackRecordSchema);
export default SnackRecord;
export { SnackRecordSchema };
