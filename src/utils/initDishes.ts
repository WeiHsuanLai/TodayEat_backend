import Dish from '../models/Dish';

const defaultDishes = [
    { name: '滷肉飯', category: '台式' },
    { name: '雞肉飯', category: '台式' },
    { name: '排骨飯', category: '台式' },
    { name: '爌肉飯', category: '台式' },
    { name: '牛肉麵', category: '台式' },
    { name: '貢丸湯', category: '台式' },
    { name: '大腸蚵仔麵線', category: '台式' },
    { name: '肉羹湯', category: '台式' },
    { name: '蛋餅', category: '台式' },
    { name: '刈包', category: '台式' },
    { name: '臭豆腐', category: '台式' },
    { name: '蚵仔煎', category: '台式' },
    { name: '豚骨拉麵', category: '日式' },
    { name: '綜合壽司', category: '日式' },
    { name: '炸豬排定食', category: '日式' },
    { name: '韓式泡菜鍋', category: '韓式' },
    { name: '石鍋拌飯', category: '韓式' },
    { name: '韓式炸雞', category: '韓式' },
    { name: '泰式打拋豬', category: '其他' },
    { name: '義大利肉醬麵', category: '義式' },
    { name: '美式起司漢堡', category: '美式' }
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
