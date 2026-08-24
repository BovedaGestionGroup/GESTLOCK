import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { generate, generateSecret, verify } from 'otplib';
import { z } from 'zod';
import { prisma } from './lib/prisma.js';
import { requireEnv } from './lib/requireEnv.js';

// ─── Secretos JWT ─────────────────────────────────────────────────────────────
// Se leen al arrancar. Si no están configurados, la app NO arranca (fallo rápido).
// Nunca usar valores por defecto (fallbacks) para secretos criptográficos.

function getJwtSecret(): string {
  return requireEnv('JWT_SECRET');
}

function getRefreshJwtSecret(): string {
  return requireEnv('JWT_REFRESH_SECRET');
}

// ─── Tokens de refresco ───────────────────────────────────────────────────────

function createUniqueRefreshToken(userId: string) {
  const randomPart = randomBytes(16).toString('hex');
  return jwt.sign(
    { sub: userId, type: 'refresh', nonce: randomPart },
    getRefreshJwtSecret(),
    { expiresIn: '7d', algorithm: 'HS256' },
  );
}

// ─── Esquemas de validación ───────────────────────────────────────────────────

const registerSchema = z
  .object({
    email: z.string().email(),
    password: z.string().min(12),
    confirmPassword: z.string().min(12).optional(),
  })
  .superRefine((data, ctx) => {
    if (data.confirmPassword !== undefined && data.password !== data.confirmPassword) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Passwords must match',
        path: ['confirmPassword'],
      });
    }
  });

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

async function hashPassword(password: string) {
  return argon2.hash(password);
}

async function verifyPassword(storedHash: string, password: string) {
  return argon2.verify(storedHash, password);
}

// ─── Cifrado de bóveda ────────────────────────────────────────────────────────
// [C-03] Derivación dinámica de clave por usuario mediante scryptSync con userSalt
function deriveEncryptionKey(secret: string, userSalt?: string) {
  const salt = userSalt || 'gestor-salt';
  return scryptSync(secret, salt, 32);
}

function encryptSecret(secret: string, key: Buffer) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('hex')}:${encrypted.toString('hex')}:${tag.toString('hex')}`;
}

function decryptSecret(payload: string, key: Buffer) {
  const [ivHex, encryptedHex, tagHex] = payload.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encrypted = Buffer.from(encryptedHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
}

// ─── Tokens de acceso ─────────────────────────────────────────────────────────

function signAccessToken(userId: string) {
  return jwt.sign({ sub: userId }, getJwtSecret(), { expiresIn: '15m', algorithm: 'HS256' });
}

// ─── MFA ──────────────────────────────────────────────────────────────────────

function generateMfaSecret() {
  return generateSecret();
}

function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function verifyMfaCode(secret: string, code: string) {
  const result = await verify({ secret, token: code });
  return result.valid;
}

// ─── Refresh tokens ───────────────────────────────────────────────────────────

function signRefreshToken(userId: string) {
  return createUniqueRefreshToken(userId);
}

async function createRefreshToken(userId: string) {
  const token = signRefreshToken(userId);
  const existing = await prisma.refreshToken.findUnique({ where: { token } });
  if (existing) {
    return existing.token;
  }
  await prisma.refreshToken.create({
    data: {
      token,
      userId,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    },
  });
  return token;
}

async function verifyRefreshToken(token: string) {
  // [M-07] Algoritmo explícito para prevenir ataques de confusión de algoritmo
  const payload = jwt.verify(token, getRefreshJwtSecret(), {
    algorithms: ['HS256'],
  }) as { sub: string };
  const stored = await prisma.refreshToken.findUnique({ where: { token } });
  if (!stored || stored.revoked || stored.expiresAt < new Date()) {
    throw new Error('Invalid refresh token');
  }
  return payload.sub;
}

async function revokeRefreshToken(token: string) {
  await prisma.refreshToken.updateMany({
    where: { token },
    data: { revoked: true },
  });
}

// ─── Autenticación ────────────────────────────────────────────────────────────
// [C-02] El auto-aprovisionamiento de admin por defecto ha sido eliminado.
// La cuenta inicial de administrador se crea con el script: apps/api/scripts/seed-admin.mjs

async function authenticateUser(email: string, password: string) {
  const normalizedEmail = normalizeEmail(email);
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (!user) throw new Error('Invalid credentials');
  const isValid = await verifyPassword(user.passwordHash, password);
  if (!isValid) throw new Error('Invalid credentials');

  // Auto-verificar SOLO usuarios legacy (creados antes de que existiera verificación de email)
  // Los usuarios nuevos tendrán verificationCode, por lo que no se auto-verificarán aquí
  if (!user.isVerified && !user.verificationCode) {
    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true },
    });
    return { ...user, isVerified: true };
  }

  return user;
}

// ─── Registro ─────────────────────────────────────────────────────────────────

async function registerUser(
  email: string,
  password: string,
  role: string = 'user',
  verificationCode?: string,
  autoVerify = false,
) {
  const normalizedEmail = normalizeEmail(email);
  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  // [A-02] No revelar si el usuario existe — el mensaje genérico se gestiona en el handler
  if (existing) throw new Error('User already exists');
  const passwordHash = await hashPassword(password);
  const user = await prisma.user.create({
    data: {
      email: normalizedEmail,
      passwordHash,
      role,
      verificationCode,
      isVerified: autoVerify || role === 'admin',
    },
  });
  return user;
}

// ─── Permisos ─────────────────────────────────────────────────────────────────

function hasPermission(userRole: string | undefined, requiredRole: string) {
  if (!userRole) return false;
  const roleHierarchy = ['user', 'auditor', 'admin'];
  return roleHierarchy.indexOf(userRole) >= roleHierarchy.indexOf(requiredRole);
}

export {
  registerSchema,
  loginSchema,
  signAccessToken,
  generateMfaSecret,
  verifyMfaCode,
  createRefreshToken,
  verifyRefreshToken,
  revokeRefreshToken,
  authenticateUser,
  registerUser,
  hasPermission,
  deriveEncryptionKey,
  encryptSecret,
  decryptSecret,
  generateVerificationCode,
  hashPassword,
};
