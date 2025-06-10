// utils/mailer.ts
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();

export const sendResetPasswordEmail = async (to: string, content: string) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_PASS,
        },
    });

    const mailOptions = {
        from: `"你的網站名稱" <${process.env.GMAIL_USER}>`,
        to,
        subject: '測試郵件',
        html: `<p>${content}</p>`,
    };

    await transporter.sendMail(mailOptions);
};
