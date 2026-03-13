import express from 'express';
import { getDishes, getCategories } from '../controllers/dish';

const router = express.Router();

/**
 * @route GET /dishes/categories
 * @desc 獲取所有可用的菜品分類
 * @access Public
 */
router.get('/categories', getCategories);

/**
 * @route GET /dishes
 * @desc 獲取所有預設菜品，支援透過 category 查詢參數進行篩選
 * @access Public
 */
router.get('/', getDishes);

export default router;
