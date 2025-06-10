import mongoose from 'mongoose';
import dotenv from 'dotenv';
import User from '../src/models/user';
import UserRole from '../src/enums/UserRole';
import '../src/utils/logger';

// 載入 .env 設定
dotenv.config();

async function createAdmin() {
    const DB_URL = process.env.DB_URL;
    const account = process.env.ADMIN_ACCOUNT;
    const password = process.env.ADMIN_PASSWORD;
    const email = process.env.ADMIN_EMAIL;

    if (!DB_URL || !account || !password) {
        throw new Error('❌ 請在 .env 中設定 DB_URL、ADMIN_ACCOUNT、ADMIN_PASSWORD');
    }

    await mongoose.connect(DB_URL);

    const exists = await User.findOne({ account });
    if (exists) {
        log(`⚠️ 管理員帳號 "${account}" 已存在`);
        await mongoose.disconnect();
        return;
    }

    await User.create({
        account,
        password,
        role: UserRole.ADMIN, // 指定為管理員
        email,
        tokens: []
    });

    log(`✅ 管理員帳號 "${account}" 建立完成`);
    await mongoose.disconnect();
}

createAdmin().catch(err => {
    logError('❌ 建立失敗', err);
    process.exit(1);
});
