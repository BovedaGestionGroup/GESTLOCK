import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { requireEnv } from '../lib/requireEnv.js';

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Unauthorized' });
    return;
  }

  const token = header.slice('Bearer '.length);

  try {
    // [C-01] Sin fallback — requireEnv lanza error si JWT_SECRET no está configurado
    // [M-07] Algoritmo explícito para prevenir ataques de confusión de algoritmo (alg:none, RS256→HS256)
    const payload = jwt.verify(token, requireEnv('JWT_SECRET'), {
      algorithms: ['HS256'],
    }) as { sub: string };
    req.userId = payload.sub;
    next();
  } catch {
    res.status(401).json({ message: 'Unauthorized' });
  }
}
