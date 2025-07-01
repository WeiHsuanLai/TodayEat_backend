import { Router } from 'express';
import axios from 'axios';
import { authMiddleware } from '../middleware/auth'

const router = Router();

router.get('/nearby-stores', authMiddleware, async (req, res) => {
    const { keyword, lat, lng } = req.query;

    if (!lat || !lng || !keyword) {
        res.status(400).json({ error: '❌ 缺少參數 lat, lng, keyword' });
        return;
    }

    try {
        const response = await axios.get(
            'https://maps.googleapis.com/maps/api/place/nearbysearch/json',
            {
                params: {
                    key: process.env.GOOGLE_API_KEY,
                    location: `${lat},${lng}`,
                    radius: 1000,
                    keyword,
                    language: 'zh-TW',
                },
            }
        );

        res.json(response.data);
    } catch (err) {
        console.error('[Google Places API Error]', err);
        res.status(500).json({ error: '❌ 無法取得地圖資料' });
    }
});

export default router;
