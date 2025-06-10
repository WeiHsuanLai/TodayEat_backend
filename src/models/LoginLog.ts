import { Schema, model } from 'mongoose';

const loginLogSchema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'user',
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
    timestamps: true,
    versionKey: false
});

export default model('login_logs', loginLogSchema);
