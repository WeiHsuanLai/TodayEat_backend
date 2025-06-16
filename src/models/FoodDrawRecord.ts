import { Schema, model } from 'mongoose';

const FoodDrawRecordSchema = new Schema({
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    meal: {
        type: String,
        enum: ['breakfast', 'lunch', 'dinner', 'midnight'],
        required: true
    },
    food: { type: String, required: true },
    date: {
        type: String,
        required: true
    },
    updatedAt: { type: Date, default: Date.now }
});

FoodDrawRecordSchema.index({ userId: 1, date: 1, meal: 1 }, { unique: true });

export default model('FoodDrawRecord', FoodDrawRecordSchema);
