import { Request, Response, NextFunction } from 'express';
import UserRole from "../enums/UserRole";
import jwt, { JwtPayload } from 'jsonwebtoken';

interface MyJwtPayload extends JwtPayload {
    id: string;
    account: string;
    role: number;
    avatar: string;
}


export const adminMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token){
        res.status(401).json({ success: false, message: '未授權' });
        return;
    } 

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret') as MyJwtPayload;

        if (decoded.role !== UserRole.ADMIN) {
            res.status(403).json({ success: false, message: '只有管理員可使用此功能' });
            return;
        }
        (req as Request & { user?: MyJwtPayload }).user = decoded;
        next();
    } catch {
        res.status(401).json({ success: false, message: '無效 token' });
        return;
    }
};
