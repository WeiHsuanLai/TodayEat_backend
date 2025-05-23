import 'dotenv/config'; //自動載入 .env
import express, { Request, Response, NextFunction,RequestHandler  } from 'express';
import mongoSanitize from 'express-mongo-sanitize'; // 防止 NoSQL 注入
import mongoose from 'mongoose';
// import cors from 'cors'; // 如有跨域需求可啟用
import { StatusCodes } from 'http-status-codes'; // 提供標準 HTTP 狀態碼常數
import i18nMiddleware from './middleware/i18n'; // 多語系中介層
import routerUser from './routes/user'; // 使用者相關路由
import helmet from 'helmet'; // 設定 HTTP 安全標頭

const app = express();
const safeMongoSanitize: RequestHandler = (req, res, next) => {
  try {
    // 處理 body
    if (req.body) {
      req.body = mongoSanitize.sanitize(req.body);
    }

    // 處理 params
    if (req.params) {
      req.params = mongoSanitize.sanitize(req.params);
    }

    // ✅ 不處理 req.query（避免錯誤）

    next();
  } catch (err) {
    next(err);
  }
};

// middleware 中介層設定
app.use(i18nMiddleware);
app.use(express.json());
app.use(safeMongoSanitize); // 清除潛在的 MongoDB 查詢語法
app.use(helmet());

// routes
app.use('/user', routerUser);

app.get('/test', (req, res) => {
  res.send(req.t('test_key'));
});

// 以上請求都沒有就進入
app.use((req, res) => {
    console.warn(`[重導向] ${req.method} ${req.originalUrl} → 外部網址`);
    res.redirect('https://www.youtube.com/watch?v=IxX_QHay02M');
});


// ✅ 全域錯誤處理 middleware（一定要放在所有 route 後面）
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
    console.error('[全域錯誤]', err);

    const fallback = '未知錯誤';
    const message = typeof req.t === 'function' ? req.t('unknown_error') : fallback;

    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
        success: false,
        message
    });
}

app.use(errorHandler as express.ErrorRequestHandler);

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
