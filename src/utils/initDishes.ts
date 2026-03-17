import Dish from '../models/Dish';

const defaultDishes = [
    { name: { zh: '滷肉飯', en: 'Braised Pork Rice' }, category: '台式' },
    { name: { zh: '雞肉飯', en: 'Chicken Rice' }, category: '台式' },
    { name: { zh: '排骨飯', en: 'Pork Chop Rice' }, category: '台式' },
    { name: { zh: '爌肉飯', en: 'Braised Pork Belly Rice' }, category: '台式' },
    { name: { zh: '牛肉麵', en: 'Beef Noodle Soup' }, category: '台式' },
    { name: { zh: '貢丸湯', en: 'Meatball Soup' }, category: '台式' },
    { name: { zh: '大腸蚵仔麵線', en: 'Intestine & Oyster Vermicelli' }, category: '台式' },
    { name: { zh: '肉羹湯', en: 'Meat Thick Soup' }, category: '台式' },
    { name: { zh: '蛋餅', en: 'Egg Crepe' }, category: '台式' },
    { name: { zh: '刈包', en: 'Gua Bao' }, category: '台式' },
    { name: { zh: '臭豆腐', en: 'Stinky Tofu' }, category: '台式' },
    { name: { zh: '蚵仔煎', en: 'Oyster Omelet' }, category: '台式' },
    { name: { zh: '豚骨拉麵', en: 'Tonkotsu Ramen' }, category: '日式' },
    { name: { zh: '綜合壽司', en: 'Assorted Sushi' }, category: '日式' },
    { name: { zh: '炸豬排定食', en: 'Tonkatsu Set' }, category: '日式' },
    { name: { zh: '韓式泡菜鍋', en: 'Kimchi Jjigae' }, category: '韓式' },
    { name: { zh: '石鍋拌飯', en: 'Bibimbap' }, category: '韓式' },
    { name: { zh: '韓式炸雞', en: 'Korean Fried Chicken' }, category: '韓式' },
    { name: { zh: '泰式打拋豬', en: 'Thai Basil Pork' }, category: '泰式' },
    { name: { zh: '義大利肉醬麵', en: 'Pasta Bolognese' }, category: '義式' },
    { name: { zh: '美式起司漢堡', en: 'American Cheese Burger' }, category: '美式' }
];

export const initDefaultDishes = async () => {
    try {
        const count = await Dish.countDocuments();
        if (count === 0) {
            console.log('📦 偵測到菜品資料庫為空，正在匯入預設台灣料理...');
            await Dish.insertMany(defaultDishes);
            console.log('✨ 預設菜品匯入完成！');
        } else {
            // console.log(`✅ 資料庫已有 ${count} 筆菜品，略過自動匯入`);
        }
    } catch (err) {
        console.error('❌ 自動匯入菜品失敗:', err);
    }
};
