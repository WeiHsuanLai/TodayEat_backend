import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Dish from '../src/models/Dish';

dotenv.config();

const defaultDishes = [
    // 台式 - 飯類/便當
    { name: { zh: '滷肉飯', en: 'Braised Pork Rice' }, category: '台式' },
    { name: { zh: '雞肉飯', en: 'Chicken Rice' }, category: '台式' },
    { name: { zh: '排骨飯', en: 'Pork Chop Rice' }, category: '台式' },
    { name: { zh: '爌肉飯', en: 'Braised Pork Belly Rice' }, category: '台式' },
    { name: { zh: '豬腳飯', en: 'Pork Knuckle Rice' }, category: '台式' },
    { name: { zh: '燒肉飯', en: 'Roasted Pork Rice' }, category: '台式' },
    { name: { zh: '鴨肉飯', en: 'Duck Rice' }, category: '台式' },

    // 台式 - 麵食/湯類
    { name: { zh: '牛肉麵', en: 'Beef Noodle Soup' }, category: '台式' },
    { name: { zh: '餛飩麵', en: 'Wonton Noodles' }, category: '台式' },
    { name: { zh: '陽春麵', en: 'Yangchun Noodles' }, category: '台式' },
    { name: { zh: '麻醬麵', en: 'Sesame Paste Noodles' }, category: '台式' },
    { name: { zh: '炸醬麵', en: 'Zha Jiang Mian' }, category: '台式' },
    { name: { zh: '涼麵', en: 'Cold Noodles' }, category: '台式' },
    { name: { zh: '炒米粉', en: 'Fried Rice Vermicelli' }, category: '台式' },
    { name: { zh: '大腸蚵仔麵線', en: 'Intestine & Oyster Vermicelli' }, category: '台式' },
    { name: { zh: '貢丸湯', en: 'Meatball Soup' }, category: '台式' },
    { name: { zh: '肉羹湯', en: 'Meat Thick Soup' }, category: '台式' },
    { name: { zh: '酸辣湯', en: 'Hot and Sour Soup' }, category: '台式' },
    { name: { zh: '蛋花湯', en: 'Egg Drop Soup' }, category: '台式' },
    { name: { zh: '虱目魚肚湯', en: 'Milkfish Belly Soup' }, category: '台式' },

    // 台式 - 小吃/點心
    { name: { zh: '刈包', en: 'Gua Bao' }, category: '台式' },
    { name: { zh: '臭豆腐', en: 'Stinky Tofu' }, category: '台式' },
    { name: { zh: '蚵仔煎', en: 'Oyster Omelet' }, category: '台式' },
    { name: { zh: '肉圓', en: 'Ba-wan' }, category: '台式' },
    { name: { zh: '碗粿', en: 'Savory Rice Pudding' }, category: '台式' },
    { name: { zh: '筒仔米糕', en: 'Tube Rice Pudding' }, category: '台式' },
    { name: { zh: '甜不辣', en: 'Tian Bu La' }, category: '台式' },
    { name: { zh: '鹹酥雞', en: 'Salt and Pepper Chicken' }, category: '台式' },
    { name: { zh: '炸雞排', en: 'Fried Chicken Fillet' }, category: '台式' },
    { name: { zh: '地瓜球', en: 'Sweet Potato Balls' }, category: '台式' },

    // 日式
    { name: { zh: '豚骨拉麵', en: 'Tonkotsu Ramen' }, category: '日式' },
    { name: { zh: '醬油拉麵', en: 'Shoyu Ramen' }, category: '日式' },
    { name: { zh: '味噌拉麵', en: 'Miso Ramen' }, category: '日式' },
    { name: { zh: '烏龍麵', en: 'Udon' }, category: '日式' },
    { name: { zh: '綜合壽司', en: 'Assorted Sushi' }, category: '日式' },
    { name: { zh: '炸豬排定食', en: 'Tonkatsu Set' }, category: '日式' },
    { name: { zh: '日式咖哩飯', en: 'Japanese Curry Rice' }, category: '日式' },

    // 韓式
    { name: { zh: '韓式泡菜鍋', en: 'Kimchi Jjigae' }, category: '韓式' },
    { name: { zh: '部隊鍋', en: 'Budae Jjigae' }, category: '韓式' },
    { name: { zh: '石鍋拌飯', en: 'Bibimbap' }, category: '韓式' },
    { name: { zh: '韓式炸雞', en: 'Korean Fried Chicken' }, category: '韓式' },

    // 泰式
    { name: { zh: '泰式打拋豬', en: 'Thai Basil Pork' }, category: '泰式' },
    { name: { zh: '泰式椒麻雞', en: 'Thai Spicy Chicken' }, category: '泰式' },
    { name: { zh: '月亮蝦餅', en: 'Moon Shrimp Cake' }, category: '泰式' },

    // 美式
    { name: { zh: '美式起司漢堡', en: 'American Cheese Burger' }, category: '美式' },
    { name: { zh: '雙層牛肉堡', en: 'Double Beef Burger' }, category: '美式' },

    // 義式
    { name: { zh: '義大利肉醬麵', en: 'Pasta Bolognese' }, category: '義式' },
    { name: { zh: '奶油培根麵', en: 'Pasta Carbonara' }, category: '義式' }
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
            console.log(`✅ 已建立菜品: ${item.name.zh}`);
        }

        console.log('✨ 台灣常見料理(多語系版)已匯入完成！');
        await mongoose.disconnect();
    } catch (err) {
        console.error('❌ 填充失敗', err);
        process.exit(1);
    }
}

seedDishes();
