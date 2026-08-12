import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'crypto';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { generate, generateSecret, verify } from 'otplib';
import { z } from 'zod';
import { prisma } from './lib/prisma.js';

function createUniqueRefreshToken(userId: string) {
  const randomPart = randomBytes(16).toString('hex');
  return jwt.sign({ sub: userId, type: 'refresh', nonce: randomPart }, getRefreshJwtSecret(), { expiresIn: '7d' });
}

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
  password: z.string().min(12),
});

function getJwtSecret() {
  return process.env.JWT_SECRET ?? 'dev-secret';
}

function getRefreshJwtSecret() {
  return process.env.JWT_REFRESH_SECRET ?? 'dev-refresh-secret';
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function getDefaultAdminCredentials() {
  return {
    email: process.env.DEFAULT_ADMIN_EMAIL ?? 'info@gestiongroup.es',
    password: process.env.DEFAULT_ADMIN_PASSWORD ?? 'Gestion2026.',
  };
}

async function hashPassword(password: string) {
  return argon2.hash(password);
}

async function verifyPassword(storedHash: string, password: string) {
  return argon2.verify(storedHash, password);
}

function deriveEncryptionKey(secret: string) {
  return scryptSync(secret, 'gestor-salt', 32);
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

function signAccessToken(userId: string) {
  return jwt.sign({ sub: userId }, getJwtSecret(), { expiresIn: '15m' });
}

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
  const payload = jwt.verify(token, getRefreshJwtSecret()) as { sub: string };
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

async function authenticateUser(email: string, password: string) {
  const normalizedEmail = normalizeEmail(email);
  let user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (!user) {
    const defaultAdmin = getDefaultAdminCredentials();
    if (normalizedEmail === defaultAdmin.email.toLowerCase() && password === defaultAdmin.password) {
      user = await registerUser(defaultAdmin.email, defaultAdmin.password, 'admin');
    }
  }

  if (!user) throw new Error('Invalid credentials');
  const isValid = await verifyPassword(user.passwordHash, password);
  if (!isValid) throw new Error('Invalid credentials');
  return user;
}

async function registerUser(email: string, password: string, role: string = 'user', verificationCode?: string) {
  const normalizedEmail = normalizeEmail(email);
  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  if (existing) throw new Error('User already exists');
  const passwordHash = await hashPassword(password);
  const user = await prisma.user.create({
    data: { email: normalizedEmail, passwordHash, role, verificationCode },
  });
  return user;
}

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
