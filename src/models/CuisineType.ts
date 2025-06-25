import mongoose from 'mongoose';

const cuisineTypeSchema = new mongoose.Schema({
    label: { type: String, required: true },
    items: { type: [String], required: true },
    imageUrl: { type: String },
}, { timestamps: true });

export const CuisineType = mongoose.model('CuisineType', cuisineTypeSchema);
