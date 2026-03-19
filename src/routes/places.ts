import { Router } from 'express';
import axios from 'axios';
import { authMiddleware } from '../middleware/auth';

const router = Router();

router.get('/nearby-stores', authMiddleware, async (req, res) => {
    const { keyword, lat, lng, radius = 1000 } = req.query;

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
                    radius: Number(radius),
                    keyword,
                    language: 'zh-TW',
                },
            }
        );

        type Place = {
            rating?: number;
            photos?: { photo_reference: string }[];
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            [key: string]: any;
        };

        const filteredResults = (response.data.results as Place[])
            .filter((place) => place.rating !== undefined)
            .map((place) => {
                const photoReference = place.photos?.[0]?.photo_reference;
                const photoUrl = photoReference
                    ? encodeURI(`https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=${photoReference}&key=${process.env.GOOGLE_API_KEY}`)
                    : null;

                return {
                    ...place,
                    photoUrl,
                };
            });

        res.json({ ...response.data, results: filteredResults });
    } catch (err) {
        console.error('[Google Places API Error]', err);
        res.status(500).json({ error: '❌ 無法取得地圖資料' });
    }
});

router.get('/details', authMiddleware, async (req, res) => {
    const { place_id } = req.query;

    if (!place_id) {
        res.status(400).json({ error: '❌ 缺少參數 place_id' });
        return;
    }

    try {
        const response = await axios.get(
            'https://maps.googleapis.com/maps/api/place/details/json',
            {
                params: {
                    key: process.env.GOOGLE_API_KEY,
                    place_id,
                    fields: 'name,rating,reviews,user_ratings_total,formatted_address,formatted_phone_number,opening_hours,website,photos,url',
                    language: 'zh-TW',
                },
            }
        );

        const placeDetails = response.data.result;

        if (placeDetails && placeDetails.photos) {
            placeDetails.photos = placeDetails.photos.map((photo: { photo_reference: string }) => {
                return {
                    ...photo,
                    photoUrl: encodeURI(`https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=${photo.photo_reference}&key=${process.env.GOOGLE_API_KEY}`),
                };
            });
        }

        res.json(response.data);
    } catch (err) {
        console.error('[Google Place Details API Error]', err);
        res.status(500).json({ error: '❌ 無法取得商家詳細資料' });
    }
});

router.get('/reviews', authMiddleware, async (req, res) => {
    const { place_id } = req.query;

    if (!place_id) {
        res.status(400).json({ error: '❌ 缺少參數 place_id' });
        return;
    }

    try {
        const response = await axios.get(
            'https://maps.googleapis.com/maps/api/place/details/json',
            {
                params: {
                    key: process.env.GOOGLE_API_KEY,
                    place_id,
                    fields: 'reviews,rating,user_ratings_total,url',
                    language: 'zh-TW',
                },
            }
        );

        res.json(response.data.result || { reviews: [] });
    } catch (err) {
        console.error('[Google Place Reviews API Error]', err);
        res.status(500).json({ error: '❌ 無法取得商家評論' });
    }
});

export default router;
