import mongoose, { Schema, model } from "mongoose";
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
        tokens:{
            type:[String],
            default: []
        },
        cart:{
            type:[cartSchema]
        },
        role:{
            type:Number,
            default: UserRole.USER,
        }
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
    tokens: string[];
    cart: ICartItem[];
    role: number;
    isModified(field: string): boolean;
}

// 密碼加密，自動檢查是否變更，若有變更就進行雜湊加密
schema.pre<IUser>('save', function (next) {
    if (this.isModified('password')) {
        this.password = bcrypt.hashSync(this.password, 10);
    }
    next();
});

// 將輸入密碼進行加密後與資料庫中的加密密碼比對，回傳 true / false
schema.methods.comparePassword = function (inputPassword: string): boolean {
    return bcrypt.compareSync(inputPassword, this.password);
};

// 建立虛擬欄位，名為'cartQuantity'，當 get 時，指向購物車陣列，並將所有 quantity 加總後回傳
schema.virtual('cartQuantity').get(function(){
    return this.cart.reduce((total, current) => {
        return total + current.quantity
    }, 0)
})

export default model<IUser>('user', schema)