import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

function getJwtSecret() {
  return process.env.JWT_SECRET ?? 'dev-secret';
}

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  const token = header.slice('Bearer '.length);

  try {
    const payload = jwt.verify(token, getJwtSecret()) as { sub: string };
    req.userId = payload.sub;
    next();
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
  }
}
