import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Dish from '../src/models/Dish';

dotenv.config();

async function listDishes() {
    const DB_URL = process.env.DB_URL;

    if (!DB_URL) {
        console.error('❌ 請在 .env 中設定 DB_URL');
        return;
    }

    try {
        await mongoose.connect(DB_URL);
        const dishes = await Dish.find({}, 'name category _id');
        
        console.log('--- 目前資料庫中的菜品清單 ---');
        dishes.forEach(dish => {
            console.log(`ID: ${dish._id} | 名稱: ${dish.name} | 分類: ${dish.category}`);
        });
        console.log(`--- 共計 ${dishes.length} 項菜品 ---`);

        await mongoose.disconnect();
    } catch (err) {
        console.error('❌ 查詢失敗', err);
    }
}

listDishes();
