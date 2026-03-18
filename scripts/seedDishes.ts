import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Dish from '../src/models/Dish';

dotenv.config();

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
    // --- 台式 (16項) ---
    { name: { zh: '滷肉飯', en: 'Braised Pork Rice' }, category: categoryMap['台式'] },
    { name: { zh: '雞肉飯', en: 'Chicken Rice' }, category: categoryMap['台式'] },
    { name: { zh: '排骨飯', en: 'Pork Chop Rice' }, category: categoryMap['台式'] },
    { name: { zh: '牛肉麵', en: 'Beef Noodle Soup' }, category: categoryMap['台式'] },
    { name: { zh: '大腸蚵仔麵線', en: 'Intestine & Oyster Vermicelli' }, category: categoryMap['台式'] },
    { name: { zh: '貢丸湯', en: 'Meatball Soup' }, category: categoryMap['台式'] },
    { name: { zh: '肉羹湯', en: 'Meat Thick Soup' }, category: categoryMap['台式'] },
    { name: { zh: '蛋餅', en: 'Egg Crepe' }, category: categoryMap['台式'] },
    { name: { zh: '刈包', en: 'Gua Bao' }, category: categoryMap['台式'] },
    { name: { zh: '臭豆腐', en: 'Stinky Tofu' }, category: categoryMap['台式'] },
    { name: { zh: '蚵仔煎', en: 'Oyster Omelet' }, category: categoryMap['台式'] },
    { name: { zh: '肉圓', en: 'Ba-wan' }, category: categoryMap['台式'] },
    { name: { zh: '甜不辣', en: 'Tian Bu La' }, category: categoryMap['台式'] },
    { name: { zh: '鹹酥雞', en: 'Salt and Pepper Chicken' }, category: categoryMap['台式'] },
    { name: { zh: '炸雞排', en: 'Fried Chicken Fillet' }, category: categoryMap['台式'] },
    { name: { zh: '地瓜球', en: 'Sweet Potato Balls' }, category: categoryMap['台式'] },

    // --- 中式 (16項) ---
    { name: { zh: '麻婆豆腐', en: 'Mapo Tofu' }, category: categoryMap['中式'] },
    { name: { zh: '宮保雞丁', en: 'Kung Pao Chicken' }, category: categoryMap['中式'] },
    { name: { zh: '糖醋排骨', en: 'Sweet and Sour Pork Ribs' }, category: categoryMap['中式'] },
    { name: { zh: '鳳梨蝦球', en: 'Pineapple Shrimp Balls' }, category: categoryMap['中式'] },
    { name: { zh: '小籠包', en: 'Xiao Long Bao' }, category: categoryMap['中式'] },
    { name: { zh: '蔥油餅', en: 'Scallion Pancake' }, category: categoryMap['中式'] },
    { name: { zh: '蒜泥白肉', en: 'Garlic Pork' }, category: categoryMap['中式'] },
    { name: { zh: '蝦仁炒飯', en: 'Shrimp Fried Rice' }, category: categoryMap['中式'] },
    { name: { zh: '番茄炒蛋', en: 'Tomato Scrambled Eggs' }, category: categoryMap['中式'] },
    { name: { zh: '回鍋肉', en: 'Twice Cooked Pork' }, category: categoryMap['中式'] },
    { name: { zh: '乾煸四季豆', en: 'Dry-fried String Beans' }, category: categoryMap['中式'] },
    { name: { zh: '魚香茄子', en: 'Yuxiang Eggplant' }, category: categoryMap['中式'] },
    { name: { zh: '咕咾肉', en: 'Sweet and Sour Pork' }, category: categoryMap['中式'] },
    { name: { zh: '清蒸魚', en: 'Steamed Fish' }, category: categoryMap['中式'] },
    { name: { zh: '廣式燒臘', en: 'Cantonese Roast Meat' }, category: categoryMap['中式'] },
    { name: { zh: '水餃', en: 'Dumplings' }, category: categoryMap['中式'] },

    // --- 日式 (16項) ---
    { name: { zh: '豚骨拉麵', en: 'Tonkotsu Ramen' }, category: categoryMap['日式'] },
    { name: { zh: '烏龍麵', en: 'Udon' }, category: categoryMap['日式'] },
    { name: { zh: '綜合壽司', en: 'Assorted Sushi' }, category: categoryMap['日式'] },
    { name: { zh: '炸豬排定食', en: 'Tonkatsu Set' }, category: categoryMap['日式'] },
    { name: { zh: '日式咖哩飯', en: 'Japanese Curry Rice' }, category: categoryMap['日式'] },
    { name: { zh: '天婦羅', en: 'Tempura' }, category: categoryMap['日式'] },
    { name: { zh: '親子丼', en: 'Oyako-don' }, category: categoryMap['日式'] },
    { name: { zh: '勝丼', en: 'Katsu-don' }, category: categoryMap['日式'] },
    { name: { zh: '牛丼', en: 'Gyudon' }, category: categoryMap['日式'] },
    { name: { zh: '蛋包飯', en: 'Omurice' }, category: categoryMap['日式'] },
    { name: { zh: '烤鯖魚', en: 'Grilled Mackerel' }, category: categoryMap['日式'] },
    { name: { zh: '茶碗蒸', en: 'Chawanmushi' }, category: categoryMap['日式'] },
    { name: { zh: '章魚燒', en: 'Takoyaki' }, category: categoryMap['日式'] },
    { name: { zh: '日式炸雞', en: 'Karaage' }, category: categoryMap['日式'] },
    { name: { zh: '蕎麥麵', en: 'Soba' }, category: categoryMap['日式'] },
    { name: { zh: '生魚片蓋飯', en: 'Chirashi-don' }, category: categoryMap['日式'] },

    // --- 韓式 (16項) ---
    { name: { zh: '韓式泡菜鍋', en: 'Kimchi Jjigae' }, category: categoryMap['韓式'] },
    { name: { zh: '部隊鍋', en: 'Budae Jjigae' }, category: categoryMap['韓式'] },
    { name: { zh: '石鍋拌飯', en: 'Bibimbap' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式炸雞', en: 'Korean Fried Chicken' }, category: categoryMap['韓式'] },
    { name: { zh: '海鮮煎餅', en: 'Seafood Pancake' }, category: categoryMap['韓式'] },
    { name: { zh: '辣炒年糕', en: 'Tteokbokki' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式豆腐鍋', en: 'Soondubu Jjigae' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式炸醬麵', en: 'Jajangmyeon' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式烤肉飯', en: 'Bulgogi Rice' }, category: categoryMap['韓式'] },
    { name: { zh: '蔘雞湯', en: 'Samgyetang' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式烤五花肉', en: 'Samgyeopsal' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式雜菜', en: 'Japchae' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式飯捲', en: 'Kimbap' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式煎餃', en: 'Mandu' }, category: categoryMap['韓式'] },
    { name: { zh: '韓式泡菜炒飯', en: 'Kimchi Fried Rice' }, category: categoryMap['韓式'] },
    { name: { zh: '春川炒雞', en: 'Dak-galbi' }, category: categoryMap['韓式'] },

    // --- 泰式 (16項) ---
    { name: { zh: '泰式打拋豬', en: 'Thai Basil Pork' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式椒麻雞', en: 'Thai Spicy Chicken' }, category: categoryMap['泰式'] },
    { name: { zh: '月亮蝦餅', en: 'Moon Shrimp Cake' }, category: categoryMap['泰式'] },
    { name: { zh: '綠咖哩雞', en: 'Green Curry Chicken' }, category: categoryMap['泰式'] },
    { name: { zh: '冬蔭功', en: 'Tom Yum Goong' }, category: categoryMap['泰式'] },
    { name: { zh: '青木瓜沙拉', en: 'Papaya Salad' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式炒河粉', en: 'Pad Thai' }, category: categoryMap['泰式'] },
    { name: { zh: '涼拌海鮮', en: 'Spicy Seafood Salad' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式烤肉', en: 'Thai BBQ' }, category: categoryMap['泰式'] },
    { name: { zh: '紅咖哩豬', en: 'Red Curry Pork' }, category: categoryMap['泰式'] },
    { name: { zh: '蝦醬空心菜', en: 'Stir-fried Morning Glory with Shrimp Paste' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式清蒸檸檬魚', en: 'Steamed Lemon Fish' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式鳳梨炒飯', en: 'Pineapple Fried Rice' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式沙嗲', en: 'Satay' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式咖哩螃蟹', en: 'Curry Crab' }, category: categoryMap['泰式'] },
    { name: { zh: '泰式香米飯', en: 'Jasmine Rice' }, category: categoryMap['泰式'] },

    // --- 美式 (16項) ---
    { name: { zh: '美式起司漢堡', en: 'American Cheese Burger' }, category: categoryMap['美式'] },
    { name: { zh: '雙層牛肉堡', en: 'Double Beef Burger' }, category: categoryMap['美式'] },
    { name: { zh: '紐約客牛排', en: 'New York Strip Steak' }, category: categoryMap['美式'] },
    { name: { zh: '烤肋排', en: 'BBQ Ribs' }, category: categoryMap['美式'] },
    { name: { zh: '炸雞翅', en: 'Buffalo Wings' }, category: categoryMap['美式'] },
    { name: { zh: '凱薩沙拉', en: 'Caesar Salad' }, category: categoryMap['美式'] },
    { name: { zh: '洋蔥圈', en: 'Onion Rings' }, category: categoryMap['美式'] },
    { name: { zh: '俱樂部三明治', en: 'Club Sandwich' }, category: categoryMap['美式'] },
    { name: { zh: '熱狗堡', en: 'Hot Dog' }, category: categoryMap['美式'] },
    { name: { zh: '炸魚薯條', en: 'Fish and Chips' }, category: categoryMap['美式'] },
    { name: { zh: '培根起司堡', en: 'Bacon Cheese Burger' }, category: categoryMap['美式'] },
    { name: { zh: '雞肉捲餅', en: 'Chicken Burrito' }, category: categoryMap['美式'] },
    { name: { zh: '美式脆薯', en: 'French Fries' }, category: categoryMap['美式'] },
    { name: { zh: '雞肉塔可', en: 'Chicken Tacos' }, category: categoryMap['美式'] },
    { name: { zh: '總匯披薩', en: 'Combination Pizza' }, category: categoryMap['美式'] },
    { name: { zh: '蛤蜊濃湯', en: 'Clam Chowder' }, category: categoryMap['美式'] },

    // --- 義式 (16項) ---
    { name: { zh: '義大利肉醬麵', en: 'Pasta Bolognese' }, category: categoryMap['義式'] },
    { name: { zh: '奶油培根麵', en: 'Pasta Carbonara' }, category: categoryMap['義式'] },
    { name: { zh: '青醬蛤蜊麵', en: 'Pesto Pasta with Clams' }, category: categoryMap['義式'] },
    { name: { zh: '瑪格麗特披薩', en: 'Margherita Pizza' }, category: categoryMap['義式'] },
    { name: { zh: '海鮮燉飯', en: 'Seafood Risotto' }, category: categoryMap['義式'] },
    { name: { zh: '墨魚麵', en: 'Squid Ink Pasta' }, category: categoryMap['義式'] },
    { name: { zh: '義式肉醬千層麵', en: 'Lasagna' }, category: categoryMap['義式'] },
    { name: { zh: '白酒蛤蜊麵', en: 'Vongole Pasta' }, category: categoryMap['義式'] },
    { name: { zh: '夏威夷披薩', en: 'Hawaiian Pizza' }, category: categoryMap['義式'] },
    { name: { zh: '野菇燉飯', en: 'Mushroom Risotto' }, category: categoryMap['義式'] },
    { name: { zh: '南瓜濃湯', en: 'Pumpkin Soup' }, category: categoryMap['義式'] },
    { name: { zh: '番茄羅勒麵', en: 'Tomato Basil Pasta' }, category: categoryMap['義式'] },
    { name: { zh: '奶油野菇麵', en: 'Creamy Mushroom Pasta' }, category: categoryMap['義式'] },
    { name: { zh: '義式番茄湯', en: 'Minestrone' }, category: categoryMap['義式'] },
    { name: { zh: '義式麵包', en: 'Bruschetta' }, category: categoryMap['義式'] },
    { name: { zh: '奶酪', en: 'Panna Cotta' }, category: categoryMap['義式'] }
];

async function seedDishes() {
    const DB_URL = process.env.DB_URL;

    if (!DB_URL) {
        throw new Error('❌ 請在 .env 中設定 DB_URL');
    }

    try {
        await mongoose.connect(DB_URL);
        console.log('✅ 已連接資料庫');

        await Dish.deleteMany({});
        console.log('🧹 已清除舊菜品資料');

        for (const item of defaultDishes) {
            await Dish.create(item);
        }

        console.log(`✨ 每類 16 項，總計 ${defaultDishes.length} 筆最常見菜品已匯入完成！`);
        await mongoose.disconnect();
    } catch (err) {
        console.error('❌ 填充失敗', err);
        process.exit(1);
    }
}

seedDishes();
