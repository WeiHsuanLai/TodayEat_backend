/* eslint-disable @typescript-eslint/no-unused-vars */
import './utils/logger';
if (process.env.CLEAR) {
  console.clear();
}

import 'dotenv/config'; //自動載入 .env
import express, { Request, Response, NextFunction, RequestHandler } from 'express';
import mongoSanitize from 'express-mongo-sanitize'; // 防止 NoSQL 注入
import mongoose, { Types } from 'mongoose';
import cors from 'cors'; // 如有跨域需求可啟用
import { StatusCodes } from 'http-status-codes'; // 提供標準 HTTP 狀態碼常數
import i18nMiddleware from './middleware/i18n'; // 多語系中介層
import helmet from 'helmet'; // 設定 HTTP 安全標頭
import cron from 'node-cron'; // 設定排程任務
import jwt, { JwtPayload } from 'jsonwebtoken';
import User from './models/user'; // 引入 mongodb 模型
import { initDefaultDishes } from './utils/initDishes';
import i18n from 'i18next';
import { formatUnixTimestamp } from './utils/formatTime';
import type { TFunction } from 'i18next';
import apiRoutes from './routes';// 路由整合
import session from 'express-session';
import VisitorLog from './models/VisitorLog';

const app = express();
const safeMongoSanitize: RequestHandler = (req, res, next) => {
  try {
    if (req.body) {
      req.body = mongoSanitize.sanitize(req.body);
    }
    if (req.params) {
      req.params = mongoSanitize.sanitize(req.params);
    }
    next();
  } catch (err) {
    next(err);
  }
};

cron.schedule('0 */8 * * *', async () => {
  log(i18n.t('🕒 cron 任務開始執行'));
  try {

    interface RawUserWithTokens {
      _id: Types.ObjectId;
      account: string;
      tokens: string[];
    }

    const usersWithTokens = await User.collection
      .find<RawUserWithTokens>({ tokens: { $exists: true, $ne: [] } })
      .toArray();

    log(i18n.t('🟡 查詢 tokens 不為空的使用者筆數：'), usersWithTokens.length);
    for (const user of usersWithTokens) {
      const originalTokens = user.tokens;
      const now = Math.floor(Date.now() / 1000);

      const validTokens = originalTokens.filter((tokenStr: string) => {
        try {
          const decoded = jwt.verify(tokenStr, process.env.JWT_SECRET || 'secret') as JwtPayload;
          const expFormatted = formatUnixTimestamp(decoded.exp);
          const nowFormatted = formatUnixTimestamp(now);
          log(i18n.t('🔍 token 有效期限：{{exp}}，當前時間：{{now}}', {
            exp: expFormatted,
            now: nowFormatted
          }));
          return decoded.exp && decoded.exp > now;
        } catch {
          logWarn(i18n.t('⚠️ 無效或過期 token 被移除'));
          return false;
        }
      });

      if (validTokens.length !== originalTokens.length) {
        await User.updateOne(
          { _id: user._id },
          { $set: { tokens: validTokens } }
        );
        log(i18n.t('🕒 cron：已更新 {{account}}，移除 {{count}} 筆 token', {
          account: user.account,
          count: originalTokens.length - validTokens.length
        }));
      }
    }

  } catch (err) {
    logError('❌ cron 任務執行失敗：', err);
  }
});



// middleware 中介層設定
app.use(i18nMiddleware);
// 安全 fallback（避免漏掛 i18nMiddleware 時 req.t 是 undefined）
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const fallbackT: TFunction = ((key: string, _options?: any) => key) as TFunction;

app.use((req, res, next) => {
  if (typeof req.t !== 'function') {
    req.t = fallbackT;
  }
  console.log('💡 req.secure:', req.secure); // 應該是 true
  console.log('🔐 req.protocol:', req.protocol); // 應該是 https
  next();
});
app.use(cors({
  origin(origin, callback) {
    const allowlist = [
      'http://localhost:9000',
      'http://127.0.0.1:3000',
      'https://WeiHsuanLai.github.io',
      'http://192.168.0.25:9000',
      'https://todayeat-frontend.onrender.com'
    ];
    if (!origin || allowlist.includes(origin)) {
      callback(null, true);
    } else {
      logWarn('❌ 被擋下的跨域來源:', origin);
      callback(null, false); // ❗ 不要丟 Error
    }
  },
  credentials: true,
  optionsSuccessStatus: 200 // 🔧 修復舊瀏覽器對 204 的兼容性問題
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(safeMongoSanitize); // 清除潛在的 MongoDB 查詢語法
app.use(helmet());
app.set('trust proxy', 1);
app.use(session({
  secret: process.env.SESSION_SECRET! || 'mySecretKey',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 10 * 60 * 1000, // 10 分鐘
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // 僅在生產環境使用 https
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    }
    }));

    // 訪客追蹤中介層：記錄不重複 IP（包含未登入訪客與登入會員）
    app.use(async (req, res, next) => {
    // 縮小排除範圍，僅排除統計路徑與靜態圖示，其餘（如菜單 /dishes, /places 等）皆計入訪客流量
    const excludedPaths = ['/favicon.ico', '/health', '/health/visitor-count', '/test'];
    if (excludedPaths.includes(req.path)) {
      return next();
    }

    try {
      const rawIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
      const ip = Array.isArray(rawIp) ? rawIp[0] : rawIp || 'unknown';
      const userAgent = req.headers['user-agent'];

      // 嘗試從 Session 或 JWT 中取得使用者 ID（如果有登入的話）
      const userId = (req.session as any)?.userId || (req.user as any)?.id || null;

      // 檢查該 IP 在過去 1 小時內是否已經記錄過
      const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
      const existingLog = await VisitorLog.findOne({
        ip,
        timestamp: { $gte: oneHourAgo }
      });

      // 如果 1 小時內沒紀錄，則新增一筆紀錄
      if (!existingLog) {
        await VisitorLog.create({
          ip,
          userAgent,
          userId // 若為 null 則代表為未登入訪客
        });

        // 取得今日凌晨 00:00 的時間
        const startOfToday = new Date();
        startOfToday.setHours(0, 0, 0, 0);

        // 計算今日總訪客數
        const todayCount = await VisitorLog.countDocuments({
          timestamp: { $gte: startOfToday }
        });

        log(`[訪客紀錄] 新訪客進入，IP: ${ip}，今日累計訪客數: ${todayCount}`);
      }
    } catch (err) {
      console.error('[Visitor Log Error]', err);
    }
    next();
    });

    app.use(apiRoutes); //路由整合// 測試key
app.get('/test', (req, res) => {
  res.send(req.t('測試鑰匙'));
  log(req.t("測試成功"));
});

app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // 無內容回應，不報錯
});

// 根目錄路由，用於處理 Render 的健康檢查
app.get('/', (req, res) => {
  res.status(StatusCodes.OK).json({
    success: true,
    message: 'TodayEat Backend is running!',
  });
});

// 以上請求都沒有就進入
app.use((req, res) => {
  logWarn(`❓ 未知請求：${req.method} ${req.originalUrl}`);
  logWarn(req.t('未知請求將導向外部網址'));
  res.redirect('https://www.youtube.com/watch?v=IxX_QHay02M');
});


// ✅ 全域錯誤處理 middleware（一定要放在所有 route 後面）

function errorHandler(err: unknown, req: Request, res: Response, _next: NextFunction) {
  logError(req.t('[全域錯誤]'), err);
  const fallback = req.t('未知錯誤');
  const message = typeof req.t === 'function' ? req.t('發生未知錯誤，請稍後再試') : fallback;

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
    throw new Error(i18n.t('❌ 缺少環境變數 DB_URL'));
  }

  try {
    mongoose.set('sanitizeFilter', false);
    await mongoose.connect(DB_URL);
    log(i18n.t('✅ 資料庫連線成功'));

    // 啟動時自動檢查並初始化菜品資料
    await initDefaultDishes();

    app.listen(PORT, () => {
      log(i18n.t('🚀 伺服器啟動：port', { port: PORT }));
    });
  } catch (err) {
    logError(i18n.t('❌ 資料庫連線失敗：'), err);
    process.exit(1); // 強制關閉
  }
}

startServer();
