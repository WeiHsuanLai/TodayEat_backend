import 'dotenv/config'; //自動載入 .env
import express, { Request, Response, NextFunction } from 'express';
import mongoose from 'mongoose';
// import cors from 'cors';
import { StatusCodes } from 'http-status-codes';
import i18nMiddleware from './middleware/i18n';
import routerUser from './routes/user';

const app = express();

// middleware
app.use(i18nMiddleware);
app.use(express.json());

// routes
app.use('/user', routerUser);

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
app.listen(process.env.PORT || 4000, async () => {
    console.log('伺服器啟動');
    const DB_URL = process.env.DB_URL;
    if (!DB_URL) {
        throw new Error('❌ 缺少環境變數 DB_URL');
    }
    await mongoose.connect(DB_URL);
    console.log('資料庫連線成功');
});
