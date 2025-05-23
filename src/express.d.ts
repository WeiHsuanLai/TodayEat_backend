import 'express';

declare module 'express' {
    export interface Request {
        __(key: string, ...args: unknown[]): string;
    }
}
