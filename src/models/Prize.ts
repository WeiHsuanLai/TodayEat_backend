import mongoose from 'mongoose';

const prizeSchema = new mongoose.Schema({
    label: { type: String, required: true },
    items: { type: [String], required: true },
    imageUrl: { type: String },
}, { timestamps: true });

export const Prize = mongoose.model('Prize', prizeSchema);
