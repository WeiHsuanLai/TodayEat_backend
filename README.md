# 🥗 TodayEat Backend

TodayEat 是一個 Node.js + MongoDB 打造的飲食記錄 / 餐點選擇服務，後端提供 API、JWT 登入認證、使用者角色管理、購物車系統等功能。

## 📚 技術棧
```
- **Node.js** + **Express**：伺服器框架
- **MongoDB** + **Mongoose**：資料儲存與模型設計
- **JWT (jsonwebtoken)**：登入驗證與權限保護
- **bcryptjs**：密碼加密
- **TypeScript**：強型別保障
- **dotenv**：環境變數管理
- **helmet** / **express-mongo-sanitize**：安全性強化
- **ts-node-dev**：開發模式自動重啟
- **i18next**：多語系支援
```

## 📁 專案結構
```
    ├── src/
    │ ├── config/
    │ ├── controllers/ # 控制器邏輯（註冊、登入、業務處理）
    │ ├── enums/ # 列舉型別（如 UserRole）
    │ ├── locales/ # 多語系資源（i18n 用）
    │ ├── middleware/ # 中介層（驗證登入、錯誤處理）
    │ ├── models/ # Mongoose 資料模型（User、Product...）
    │ ├── routes/ # API 路由定義
    │ ├── utils/ # 工具函式（驗證、加解密等）
    │ ├── index.ts # 應用主入口（Express 初始化）
    │ ├── express.d.ts # 自定義 Express 擴充型別
    │ ├── global.d.ts # 全域型別定義
    │ └── custom-types.d.ts # 專案內部自定義型別
    ├── .env # 環境變數
    ├── package.json
    ├── tsconfig.json
    ├── README.md
    └── .gitignore
```

# 建立環境變數 .env
```
DB_URL = mongodb+srv://<username>:<password>@<cluster-id>.mongodb.net/<database-name>
PORT=4000
ADMIN_ACCOUNT=設定管理員帳號
ADMIN_PASSWORD=設定管理員密碼
```

# 啟動伺服器
```
npm run dev
```

# 建立管理員
```
npm run create-admin
```