import mongoose, { Schema, Document } from 'mongoose';

export interface ILoginLog extends Document {
    userId: mongoose.Types.ObjectId | Record<string, unknown>;
    action: 'login' | 'logout';
    timestamp: Date;
    ip?: string;
    userAgent?: string;
}

const schema = new Schema<ILoginLog>({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    },
    action: {
        type: String,
        enum: ['login', 'logout'],
        required: true,
    },
    timestamp: {
        type: Date,
        default: Date.now,
    },
    ip: String,
    userAgent: String,
}, {
    versionKey: false
});

export default mongoose.model<ILoginLog>('LoginLog', schema, 'login_logs');
