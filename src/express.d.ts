import 'express-serve-static-core';

declare module 'express-serve-static-core' {
    interface Request {
        __: (key: string, ...args: unknown[]) => string;
    }
}
