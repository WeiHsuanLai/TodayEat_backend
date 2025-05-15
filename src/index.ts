import 'dotenv/config'; //自動載入 .env
import express, { Request, Response, NextFunction } from 'express';
import mongoSanitize from 'express-mongo-sanitize';
import mongoose from 'mongoose';
// import cors from 'cors';
import { StatusCodes } from 'http-status-codes';
import i18nMiddleware from './middleware/i18n';
import routerUser from './routes/user';
import helmet from 'helmet';

const app = express();

// middleware
app.use(i18nMiddleware);
app.use(express.json());
app.use(mongoSanitize());
app.use(helmet());

// routes
app.use('/user', routerUser);

// 以上請求都沒有就進入
app.all('*', (req: Request, res: Response) => {
    console.warn(`[重導向] ${req.method} ${req.originalUrl} → 外部網址`);
    res.redirect('https://www.youtube.com/watch?v=IxX_QHay02M');
});


// ✅ 全域錯誤處理 middleware（一定要放在所有 route 後面）
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
    console.error('[全域錯誤]', err);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message: '未知錯誤'
    });
}

app.use(errorHandler);

// start server
async function startServer() {
    const PORT = process.env.PORT || 4000;
    const DB_URL = process.env.DB_URL;

    if (!DB_URL) {
        throw new Error('❌ 缺少環境變數 DB_URL');
    }

    try {
        mongoose.set('sanitizeFilter', true);
        await mongoose.connect(DB_URL);
        console.log('✅ 資料庫連線成功');

        app.listen(PORT, () => {
            console.log(`🚀 伺服器啟動：port ${PORT}`);
        });
    } catch (err) {
        console.error('❌ 資料庫連線失敗：', err);
        process.exit(1); // 強制關閉
    }
}

startServer();
