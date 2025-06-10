import mongoose, { Schema } from 'mongoose';

const schema = new Schema({
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

export default mongoose.model('LoginLog', schema, 'login_logs');
