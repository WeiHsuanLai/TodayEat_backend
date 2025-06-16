import { Schema, model } from 'mongoose';

const SnackRecordSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    snack: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

export default model('SnackRecord', SnackRecordSchema);
