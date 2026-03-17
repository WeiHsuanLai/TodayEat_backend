import mongoose, { Schema, Document } from 'mongoose';

export interface IDish extends Document {
    name: {
        zh: string;
        en: string;
    };
    category: string;
    image?: string;
}

const dishSchema: Schema = new Schema({
    name: {
        zh: {
            type: String,
            required: [true, '中文菜品名稱為必填'],
            trim: true,
        },
        en: {
            type: String,
            required: [true, '英文菜品名稱為必填'],
            trim: true,
        }
    },
    category: {
        type: String,
        required: [true, '分類為必填'],
        enum: ['台式', '日式', '美式', '中式', '義式', '韓式', '泰式', '其他'],
        default: '其他',
    },
    image: {
        type: String,
        default: '',
    }
}, {
    timestamps: true,
    versionKey: false,
});

// 使用 'products' 作為模型名稱，以與 user.ts 中的 ref 對齊
export default mongoose.model<IDish>('products', dishSchema);
