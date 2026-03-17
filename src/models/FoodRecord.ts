import mongoose, { Schema, Document } from 'mongoose';

export interface IFoodRecord extends Document {
    userId: mongoose.Types.ObjectId;
    dishId: mongoose.Types.ObjectId;
    dishName: {
        zh: string;
        en: string;
    };
    note?: string;
}

const foodRecordSchema: Schema = new Schema({
    userId: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: [true, '使用者 ID 為必填'],
    },
    dishId: {
        type: Schema.Types.ObjectId,
        ref: 'products',
        required: false,
    },
    dishName: {
        zh: {
            type: String,
            required: [true, '中文菜品名稱為必填'],
        },
        en: {
            type: String,
            required: [true, '英文菜品名稱為必填'],
        }
    },
    note: {
        type: String,
        default: '',
    }
}, {
    timestamps: true,
    versionKey: false,
});

export default mongoose.model<IFoodRecord>('FoodRecord', foodRecordSchema);
