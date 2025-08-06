// src\controllers\auth.ts
import { Request, Response } from 'express';
import svgCaptcha from 'svg-captcha';

export const getCaptcha = (req: Request, res: Response) => {
    const captcha = svgCaptcha.create({
        size: 5,
        noise: 3,
        color: true,
        background: '#f2f2f2'
    });

    // 建議用 session 或 Redis 儲存
    req.session.captcha = captcha.text.toLowerCase();

    res.type('svg');
    res.send(captcha.data);
};

// 驗證使用者輸入的驗證碼
export const verifyCaptcha = (req: Request, res: Response) => {
    const { captcha } = req.body;

    if (!captcha) {
        res.status(400).json({
            success: false,
            message: '請輸入驗證碼',
        });
        return;
    }

    const sessionCaptcha = req.session?.captcha;

    if (!sessionCaptcha) {
        res.status(400).json({
            success: false,
            message: '驗證碼已過期或不存在，請重新取得',
        });
        return;
    }

    const isValid = captcha.toLowerCase() === sessionCaptcha.toLowerCase();

    if (!isValid) {
        res.status(400).json({
            success: false,
            message: '驗證碼錯誤',
        });
        return;
    }

    // 通過後刪除，避免重用
    delete req.session.captcha;

    res.status(200).json({
        success: true,
        message: '驗證成功',
    });
    return;
};