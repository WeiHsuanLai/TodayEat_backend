import express from 'express';
import { create } from '../controllers/user';
const router = express.Router();

router.post('/', create);


router.get('/', (req, res) => {
    res.send('Hello from user route');
});

export default router; 
