import mongoose from 'mongoose';

const mealPeriodPresetSchema = new mongoose.Schema({
    label: { type: String, required: true, unique: true },
    items: { type: [String], required: true, default: [] },
    imageUrl: { type: String },
}, { timestamps: true });

export const MealPeriodPreset = mongoose.model('MealPeriodPreset', mealPeriodPresetSchema);
