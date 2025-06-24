import mongoose from 'mongoose';

const mealPeriodPresetSchema = new mongoose.Schema({
  meal: { type: String, required: true },         // 例如：breakfast, lunch...
  items: { type: [String], required: true },       // 料理項目
});

export const MealPeriodPreset = mongoose.model('MealPeriodPreset', mealPeriodPresetSchema);
