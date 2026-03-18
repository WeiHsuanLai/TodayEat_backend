import Dish from '../models/Dish';

const categoryMap: { [key: string]: { zh: string; en: string } } = {
    '台式': { zh: '台式', en: 'Taiwanese' },
    '日式': { zh: '日式', en: 'Japanese' },
    '韓式': { zh: '韓式', en: 'Korean' },
    '泰式': { zh: '泰式', en: 'Thai' },
    '義式': { zh: '義式', en: 'Italian' },
    '美式': { zh: '美式', en: 'American' },
    '中式': { zh: '中式', en: 'Chinese' },
    '其他': { zh: '其他', en: 'Other' }
};

const defaultDishes = [
    // --- 台式 ---
    { name: { zh: '滷肉飯', en: 'Braised Pork Rice' }, category: categoryMap['台式'] },
    { name: { zh: '雞肉飯', en: 'Chicken Rice' }, category: categoryMap['台式'] },
    { name: { zh: '排骨飯', en: 'Pork Chop Rice' }, category: categoryMap['台式'] },
    { name: { zh: '爌肉飯', en: 'Braised Pork Belly Rice' }, category: categoryMap['台式'] },
    { name: { zh: '牛肉麵', en: 'Beef Noodle Soup' }, category: categoryMap['台式'] },
    { name: { zh: '大腸蚵仔麵線', en: 'Intestine & Oyster Vermicelli' }, category: categoryMap['台式'] },
    { name: { zh: '臭豆腐', en: 'Stinky Tofu' }, category: categoryMap['台式'] },
    { name: { zh: '蚵仔煎', en: 'Oyster Omelet' }, category: categoryMap['台式'] },
    { name: { zh: '鹹酥雞', en: 'Salt and Pepper Chicken' }, category: categoryMap['台式'] },
    { name: { zh: '炸雞排', en: 'Fried Chicken Fillet' }, category: categoryMap['台式'] },

    // --- 中式 ---
    { name: { zh: '麻婆豆腐', en: 'Mapo Tofu' }, category: categoryMap['中式'] },
    { name: { zh: '宮保雞丁', en: 'Kung Pao Chicken' }, category: categoryMap['中式'] },
    { name: { zh: '糖醋排骨', en: 'Sweet and Sour Pork Ribs' }, category: categoryMap['中式'] },
    { name: { zh: '小籠包', en: 'Xiao Long Bao' }, category: categoryMap['中式'] },
    { name: { zh: '蝦仁炒飯', en: 'Shrimp Fried Rice' }, category: categoryMap['中式'] },

    // --- 日式 ---
    { name: { zh: '豚骨拉麵', en: 'Tonkotsu Ramen' }, category: categoryMap['日式'] },
    { name: { zh: '綜合壽司', en: 'Assorted Sushi' }, category: categoryMap['日式'] },
    { name: { zh: '炸豬排定食', en: 'Tonkatsu Set' }, category: categoryMap['日式'] },
    { name: { zh: '天婦羅', en: 'Tempura' }, category: categoryMap['日式'] },

    // --- 韓式 ---
    { name: { zh: '韓式泡菜鍋', en: 'Kimchi Jjigae' }, category: categoryMap['韓式'] },
    { name: { zh: '石鍋拌飯', en: 'Bibimbap' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式炸雞', en: 'Korean Fried Chicken' }, category: categoryMap['韓式'] },

    // --- 泰式 ---
    { name: { zh: '泰式打拋豬', en: 'Thai Basil Pork' }, category: categoryMap['泰式'] },
    { name: { zh: '冬蔭功', en: 'Tom Yum Goong' }, category: categoryMap['泰式'] },
    { name: { zh: '月亮蝦餅', en: 'Moon Shrimp Cake' }, category: categoryMap['泰式'] },

    // --- 義式 ---
    { name: { zh: '義大利肉醬麵', en: 'Pasta Bolognese' }, category: categoryMap['義式'] },
    { name: { zh: '瑪格麗特披薩', en: 'Margherita Pizza' }, category: categoryMap['義式'] },
    { name: { zh: '海鮮燉飯', en: 'Seafood Risotto' }, category: categoryMap['義式'] },

    // --- 美式 ---
    { name: { zh: '美式起司漢堡', en: 'American Cheese Burger' }, category: categoryMap['美式'] },
    { name: { zh: '烤肋排', en: 'BBQ Ribs' }, category: categoryMap['美式'] },
    { name: { zh: '炸雞翅', en: 'Buffalo Wings' }, category: categoryMap['美式'] }
];

export const initDefaultDishes = async () => {
    try {
        const count = await Dish.countDocuments();
        if (count === 0) {
            console.log('📦 偵測到菜品資料庫為空，正在匯入預設料理...');
            await Dish.insertMany(defaultDishes);
            console.log('✨ 預設菜品匯入完成！');
        }
    } catch (err) {
        console.error('❌ 自動匯入菜品失敗:', err);
    }
};
