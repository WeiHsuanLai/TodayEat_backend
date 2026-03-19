import mongoose, { Schema } from 'mongoose';

const schema = new Schema({
    ip: {
        type: String,
        required: true,
        index: true,
    },
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        default: null,
    },
    timestamp: {
        type: Date,
        default: Date.now,
        index: true,
    },
    userAgent: String,
}, {
    versionKey: false
});

// 設定 30 天後自動刪除舊紀錄，節省資料庫空間
schema.index({ timestamp: 1 }, { expireAfterSeconds: 2592000 });

export default mongoose.model('VisitorLog', schema, 'visitor_logs');
