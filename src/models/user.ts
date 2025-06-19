// models/user.ts
import mongoose, { Schema, model, Query } from "mongoose";
import validator from "validator";
import bcrypt from 'bcryptjs';
import UserRole from "../enums/UserRole"

// 控制購物車儲存
const cartSchema = new Schema({
    p_id: {
        type: Schema.Types.ObjectId,
        ref: 'products',
        required:[true,'使用者購物車必填']
    },
    quantity: {
        type: Number,
        default: 1,
        min: [1, '使用者購物車數量不能小於 1'],
    }
})

// 控制資料儲存
const schema = new Schema(
    {
        account:{
            type:String,
            required:[true,'使用者帳號必填'],
            minlength:[4,'使用者帳號長度不符'],
            maxlength:[20,'使用者帳號長度不符'],
            unique:true,
            validate: {
                validator: (value: string) => validator.isAlphanumeric(value),
                message: '使用者格式錯誤'
            }
        },
        password:{
            type:String,
            required:[true,'使用者密碼必填'],
            minlength:[4,'使用者密碼長度不符'],
        },
        email: {
            type: String,
            required: [true, '使用者 Email 必填'],
            unique: true,
            lowercase: true,
            validate: {
                validator: (value: string) => validator.isEmail(value),
                message: 'Email 格式錯誤'
            }
        },
        tokens:{
            type:[String],
            default: []
        },
        avatar: {
            type: String,
            default: 'https://api.dicebear.com/7.x/avataaars/svg?seed=${username}',
        },
        cart:{
            type:[cartSchema]
        },
        customItems: {
            type: Map,
            of: [String],
            default: {}
        },
        role:{
            type:Number,
            default: UserRole.USER,
        },
        lastLoginAt: {
            type: Date
        },
        lastLogoutAt: {
            type: Date
        },
        originalAccount: {
            type: String,
            select: false,
        },
        originalEmail: {
            type: String,
            select: false,
        },
        isDeleted: {
            type: Boolean,
            default: false,
        },
        deletedAt: Date,
    },
    {
        timestamps: true,
        versionKey: false,
        toJSON: { virtuals: true },
        toObject: { virtuals: true },
    }
)

// 定義購物車型別
interface ICartItem {
    p_id: mongoose.Types.ObjectId;
    quantity: number;
}

// 定義使用者介面
interface IUser extends mongoose.Document {
    account: string;
    password: string;
    email: string;
    tokens: string[];
    avatar?: string;
    cart: ICartItem[];
    role: number;
    lastLoginAt?: Date;
    lastLogoutAt?: Date; 
    customItems: Map<string, string[]>;
    isModified(field: string): boolean;
}

// 密碼加密，自動檢查是否變更，若有變更就進行雜湊加密
schema.pre<IUser>('save', async function () {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
});

// 自動排除掉已經被註銷（isDeleted: true）的使用者
function applyNotDeletedFilter(this: Query<unknown, IUser>, next: () => void) {
    this.where({ isDeleted: false });
    next();
}
schema.pre(/^find/, applyNotDeletedFilter);
schema.pre('findOneAndUpdate', applyNotDeletedFilter);

// 將輸入密碼進行加密後與資料庫中的加密密碼比對，回傳 true / false
schema.methods.comparePassword = function (inputPassword: string): boolean {
    return bcrypt.compareSync(inputPassword, this.password);
};

// 建立虛擬欄位，名為'cartQuantity'，當 get 時，指向購物車陣列，並將所有 quantity 加總後回傳
schema.virtual('cartQuantity').get(function(){
    if (!Array.isArray(this.cart)) return 0;
    return this.cart.reduce((total, current) => {
        return total + current.quantity
    }, 0)
})

schema.virtual('foodDraws', {
    ref: 'FoodDrawRecord',
    localField: '_id',
    foreignField: 'userId'
});

schema.virtual('snacks', {
    ref: 'SnackRecord',
    localField: '_id',
    foreignField: 'userId'
});

export default model<IUser>('User', schema)