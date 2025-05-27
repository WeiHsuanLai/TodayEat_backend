import express from 'express';
import { create } from '../controllers/user';
import { body } from 'express-validator';
import { login } from '../controllers/user';
const router = express.Router();

router.post(
    '/',
    [
        body('account')
        .isLength({ min: 4, max: 20 }).withMessage('帳號長度應為4~20')
        .isAlphanumeric().withMessage('帳號只能包含英文與數字'),
        body('password')
        .isLength({ min: 4 }).withMessage('密碼長度至少4碼'),
    ],
    create
);

router.post('/login', login);

router.get('/', (req, res) => {
    res.send('Hello from user route');
});

export default router; 
