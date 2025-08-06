import 'express-session';

declare module 'express-session' {
    interface SessionData {
        captcha?: string;
        user?: {
            id: string;
            account: string;
            role: number;
        };
    }
}
