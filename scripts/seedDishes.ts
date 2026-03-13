import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Dish from '../src/models/Dish';

dotenv.config();

const defaultDishes = [
    // 台式 - 飯類/便當
    { name: '滷肉飯', category: '台式' },
    { name: '雞肉飯', category: '台式' },
    { name: '排骨飯', category: '台式' },
    { name: '爌肉飯', category: '台式' },

    // 台式 - 麵食/湯類
    { name: '牛肉麵', category: '台式' },
    { name: '貢丸湯', category: '台式' },
    { name: '大腸蚵仔麵線', category: '台式' },
    { name: '肉羹湯', category: '台式' },

    // 台式 - 小吃/早餐
    { name: '蛋餅', category: '台式' },
    { name: '刈包', category: '台式' },
    { name: '臭豆腐', category: '台式' },
    { name: '蚵仔煎', category: '台式' },

    // 日式 (台灣常見)
    { name: '豚骨拉麵', category: '日式' },
    { name: '綜合壽司', category: '日式' },
    { name: '炸豬排定食', category: '日式' },

    // 韓式 (台灣常見)
    { name: '韓式泡菜鍋', category: '韓式' },
    { name: '石鍋拌飯', category: '韓式' },
    { name: '韓式炸雞', category: '韓式' },

    // 其他熱門料理
    { name: '泰式打拋豬', category: '其他' },
    { name: '義大利肉醬麵', category: '義式' },
    { name: '美式起司漢堡', category: '美式' }
];

async function seedDishes() {
    const DB_URL = process.env.DB_URL;

    if (!DB_URL) {
        throw new Error('❌ 請在 .env 中設定 DB_URL');
    }

    try {
        await mongoose.connect(DB_URL);
        console.log('✅ 已連接資料庫');

        // 先清除現有資料
        await Dish.deleteMany({});
        console.log('🧹 已清除舊菜品資料');

        for (const item of defaultDishes) {
            await Dish.create(item);
            console.log(`✅ 已建立菜品: ${item.name}`);
        }

        console.log('✨ 台灣常見料理(精簡版)已匯入完成！');
        await mongoose.disconnect();
    } catch (err) {
        console.error('❌ 填充失敗', err);
        process.exit(1);
    }
}

seedDishes();
