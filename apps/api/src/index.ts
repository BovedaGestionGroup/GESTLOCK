import express from 'express';
import { randomBytes } from 'crypto';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { authMiddleware } from './middleware/authMiddleware.js';
import {
  authenticateUser,
  createRefreshToken,
  decryptSecret,
  deriveEncryptionKey,
  encryptSecret,
  generateMfaSecret,
  hasPermission,
  loginSchema,
  registerSchema,
  verifyMfaCode,
  registerUser,
  revokeRefreshToken,
  signAccessToken,
  verifyRefreshToken,
  generateVerificationCode,
  hashPassword,
} from './auth.js';
import { sendVerificationEmail, sendPasswordResetEmail } from './email.js';
import { prisma } from './lib/prisma.js';

async function createAuditLog(userId: string | undefined, action: string, details: string, metadata?: Record<string, string | undefined>) {
  await prisma.auditLog.create({
    data: {
      userId,
      action,
      details: JSON.stringify({ ...metadata, details }),
      ipAddress: metadata?.ipAddress,
      userAgent: metadata?.userAgent,
    },
  });
}

function getRouteParam(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] ?? '' : value ?? '';
}

dotenv.config();

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(cookieParser());
app.use(express.json());
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' http://localhost:3000");
  next();
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'api' });
});

app.post('/auth/register', async (req, res) => {
  try {
    const parsed = registerSchema.parse(req.body);
    const requestedRole = typeof req.body.role === 'string' ? req.body.role : 'user';
    const code = generateVerificationCode();
    const user = await registerUser(parsed.email, parsed.password, requestedRole, code);
    
    // Send verification email — log error but don't fail registration
    try {
      await sendVerificationEmail(user.email, code);
      console.log(`[AUTH] Verification email sent to ${user.email}`);
    } catch (emailError) {
      console.error(`[AUTH] Failed to send verification email to ${user.email}:`, emailError instanceof Error ? emailError.message : emailError);
    }

    await createAuditLog(user.id, 'register', 'User registered, pending verification', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });
    
    res.status(201).json({ message: 'User registered. Please verify your email.' });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Registration failed' });
  }
});

app.post('/auth/verify-email', async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      res.status(400).json({ message: 'Email and code are required' });
      return;
    }
    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    if (user.isVerified) {
      res.status(400).json({ message: 'Email is already verified' });
      return;
    }
    if (user.verificationCode !== code) {
      res.status(400).json({ message: 'Invalid verification code' });
      return;
    }
    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, verificationCode: null },
    });
    await createAuditLog(user.id, 'verify_email', 'User verified email', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });
    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Verification failed' });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const parsed = loginSchema.parse(req.body);
    const user = await authenticateUser(parsed.email, parsed.password);
    const code = typeof req.body.code === 'string' ? req.body.code : undefined;

    if (!user.isVerified) {
      res.status(403).json({ message: 'Email not verified. Please check your inbox for the verification code.' });
      return;
    }

    if (user.mfaEnabled) {
      if (!user.mfaSecret || !code || !(await verifyMfaCode(user.mfaSecret, code))) {
        res.status(401).json({ message: 'MFA code required' });
        return;
      }
    }

    const accessToken = signAccessToken(user.id);
    const refreshToken = await createRefreshToken(user.id);
    await createAuditLog(user.id, 'login', 'User logged in', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({ accessToken, refreshToken, user: { id: user.id, email: user.email, role: user.role } });
  } catch (error) {
    res.status(401).json({ message: error instanceof Error ? error.message : 'Login failed' });
  }
});

app.post('/auth/mfa/setup', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }

    const secret = generateMfaSecret();
    res.json({ secret, otpauthUrl: `otpauth://totp/Gestor%20Contraseñas%20Empresarial:${encodeURIComponent(user.email)}?secret=${secret}&issuer=Gestor%20Contraseñas%20Empresarial` });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to setup MFA' });
  }
});

app.post('/auth/mfa/verify', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const code = typeof req.body.code === 'string' ? req.body.code : undefined;
    const secret = typeof req.body.secret === 'string' ? req.body.secret : undefined;

    if (!code || !secret || !(await verifyMfaCode(secret, code))) {
      res.status(401).json({ message: 'Invalid MFA code' });
      return;
    }

    await prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true, mfaSecret: secret },
    });

    res.json({ message: 'MFA enabled' });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to verify MFA' });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    res.json({ user: { id: user.id, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to load user' });
  }
});

app.get('/audit/logs', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || !hasPermission(actor.role, 'auditor')) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const action = typeof req.query.action === 'string' ? req.query.action : undefined;
    const logs = await prisma.auditLog.findMany({
      where: action ? { action } : {},
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    res.json({ logs });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to load audit logs' });
  }
});

app.get('/admin/users', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || !hasPermission(actor.role, 'admin')) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        role: true,
        mfaEnabled: true,
        isVerified: true,
        createdAt: true,
      },
      orderBy: { createdAt: 'asc' },
    });

    res.json({ users });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to list users' });
  }
});

app.delete('/admin/users/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }
    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || !hasPermission(actor.role, 'admin')) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }
    const targetId = getRouteParam(req.params.id);
    if (targetId === userId) {
      res.status(400).json({ message: 'No puedes eliminar tu propia cuenta' });
      return;
    }
    await prisma.user.delete({ where: { id: targetId } });
    await createAuditLog(userId, 'admin_delete_user', 'User deleted', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
    });
    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Unable to delete user' });
  }
});

app.post('/admin/users/:id/verify', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) { res.status(401).json({ message: 'Unauthorized' }); return; }
    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || !hasPermission(actor.role, 'admin')) { res.status(403).json({ message: 'Forbidden' }); return; }
    const targetId = getRouteParam(req.params.id);
    await prisma.user.update({
      where: { id: targetId },
      data: { isVerified: true, verificationCode: null },
    });
    await createAuditLog(userId, 'admin_verify_user', 'User manually verified', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
    });
    res.json({ message: 'User verified' });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Unable to verify user' });
  }
});

app.post('/admin/users/:id/send-reset-password', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }
    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || !hasPermission(actor.role, 'admin')) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }
    const targetId = getRouteParam(req.params.id);
    const target = await prisma.user.findUnique({ where: { id: targetId } });
    if (!target) {
      res.status(404).json({ message: 'User not found' });
      return;
    }
    const token = randomBytes(32).toString('hex');
    await prisma.passwordResetToken.create({
      data: {
        token,
        userId: targetId,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    });
    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    const resetUrl = `${appUrl}?resetToken=${token}&email=${encodeURIComponent(target.email)}`;
    await sendPasswordResetEmail(target.email, resetUrl);
    await createAuditLog(userId, 'admin_send_reset_password', 'Password reset sent', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
    });
    res.json({ message: `Reset email sent to ${target.email}` });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to send reset email' });
  }
});

app.post('/auth/reset-password', async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    if (!token || !email || !newPassword) {
      res.status(400).json({ message: 'Token, email and new password are required' });
      return;
    }
    if (typeof newPassword !== 'string' || newPassword.length < 12) {
      res.status(400).json({ message: 'La contraseña debe tener al menos 12 caracteres' });
      return;
    }
    const resetToken = await prisma.passwordResetToken.findUnique({ where: { token } });
    if (!resetToken || resetToken.used || resetToken.expiresAt < new Date()) {
      res.status(400).json({ message: 'El enlace es inválido o ha expirado' });
      return;
    }
    const user = await prisma.user.findUnique({ where: { id: resetToken.userId } });
    if (!user || user.email !== email.toLowerCase().trim()) {
      res.status(400).json({ message: 'Token o email no válido' });
      return;
    }
    const passwordHash = await hashPassword(newPassword);
    await prisma.user.update({
      where: { id: user.id },
      data: { passwordHash, isVerified: true },
    });
    await prisma.passwordResetToken.update({
      where: { token },
      data: { used: true },
    });
    await createAuditLog(user.id, 'reset_password', 'Password reset completed', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });
    res.json({ message: 'Contraseña restablecida correctamente' });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Reset failed' });
  }
});

app.put('/admin/users/:id/role', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || !hasPermission(actor.role, 'admin')) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const targetId = getRouteParam(req.params.id);
    const role = typeof req.body.role === 'string' ? req.body.role : undefined;
    const validRoles = ['user', 'auditor', 'admin'];

    if (!role || !validRoles.includes(role)) {
      res.status(400).json({ message: 'Invalid role' });
      return;
    }

    const updatedUser = await prisma.user.update({
      where: { id: targetId },
      data: { role },
      select: {
        id: true,
        email: true,
        role: true,
      },
    });

    await createAuditLog(userId, 'admin_role_update', 'Role updated', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
      role,
    });

    res.json({ user: updatedUser });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Unable to update role' });
  }
});

app.post('/auth/logout', authMiddleware, async (req, res) => {
  try {
    const refreshToken = req.headers['x-refresh-token'];
    if (typeof refreshToken === 'string' && refreshToken.length > 0) {
      await revokeRefreshToken(refreshToken);
    }
    if (req.userId) {
      await createAuditLog(req.userId, 'logout', 'User logged out', {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      });
    }
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out' });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Logout failed' });
  }
});

app.post('/auth/refresh', async (req, res) => {
  try {
    const refreshToken = typeof req.headers['x-refresh-token'] === 'string' && req.headers['x-refresh-token']
      ? req.headers['x-refresh-token']
      : req.cookies?.refreshToken;
    if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
      res.status(401).json({ message: 'Refresh token required' });
      return;
    }
    const userId = await verifyRefreshToken(refreshToken);
    const accessToken = signAccessToken(userId);
    const nextRefreshToken = await createRefreshToken(userId);
    res.json({ accessToken, refreshToken: nextRefreshToken });
  } catch (error) {
    res.status(401).json({ message: error instanceof Error ? error.message : 'Refresh failed' });
  }
});

app.post('/vault/entries', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const encryptionKey = deriveEncryptionKey(process.env.VAULT_MASTER_SECRET ?? 'dev-master-secret');
    const encryptedPassword = encryptSecret(String(req.body.password ?? ''), encryptionKey);

    const item = {
      id: `entry-${Date.now()}`,
      userId,
      name: req.body.name,
      url: req.body.url,
      username: req.body.username,
      password: encryptedPassword,
      notes: req.body.notes,
      createdAt: new Date().toISOString(),
    };

    await prisma.vaultEntry.create({
      data: item,
    });

    await createAuditLog(userId, 'vault_create', 'Vault entry created', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId: item.id,
    });

    res.status(201).json({
      item: {
        ...item,
        password: String(req.body.password ?? ''),
      },
    });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Vault creation failed' });
  }
});

app.get('/vault/entries', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    const search = typeof req.query.search === 'string' ? req.query.search : undefined;
    const items = await prisma.vaultEntry.findMany({
      where: {
        userId: actor?.role === 'admin' ? undefined : actor?.id ?? userId,
        includeAll: actor?.role === 'admin',
      },
      search,
    });
    const encryptionKey = deriveEncryptionKey(process.env.VAULT_MASTER_SECRET ?? 'dev-master-secret');
    const decryptedItems = items.map((entry: any) => ({
      ...entry,
      password: decryptSecret(entry.password, encryptionKey),
    }));
    res.json({ items: decryptedItems });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to list vault entries' });
  }
});

app.get('/vault/entries/:id/history', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const entryId = getRouteParam(req.params.id);

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || (!hasPermission(actor.role, 'admin') && !hasPermission(actor.role, 'auditor'))) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const logs = await prisma.auditLog.findMany({
      where: {
        details: {
          contains: `"entryId":"${entryId}"`
        }
      },
      include: {
        user: true
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json({ logs });
  } catch (error) {
    res.status(500).json({ message: error instanceof Error ? error.message : 'Unable to load history' });
  }
});

app.post('/vault/entries/:id/shares', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    const entryId = getRouteParam(req.params.id);
    const targetUserId = typeof req.body.userId === 'string' ? req.body.userId : undefined;

    if (!actor || (!hasPermission(actor.role, 'admin') && actor.id !== userId)) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    if (!targetUserId) {
      res.status(400).json({ message: 'User is required' });
      return;
    }

    const entry = await prisma.vaultEntry.findUnique({ where: { id: entryId } });
    const targetUser = await prisma.user.findUnique({ where: { id: targetUserId } });

    if (!entry || !targetUser) {
      res.status(404).json({ message: 'Vault entry or user not found' });
      return;
    }

    const existingShare = await prisma.vaultEntryShare.findFirst({ where: { entryId, userId: targetUserId } });
    if (existingShare) {
      res.status(200).json({ share: existingShare });
      return;
    }

    const share = await prisma.vaultEntryShare.create({ data: { entryId, userId: targetUserId } });
    await createAuditLog(userId, 'vault_share', 'Vault entry shared', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId,
      targetUserId,
    });

    res.status(201).json({ share });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Unable to share vault entry' });
  }
});

app.put('/vault/entries/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const entryId = getRouteParam(req.params.id);

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    const existing = await prisma.vaultEntry.findMany({
      where: {
        userId: actor?.role === 'admin' ? undefined : userId,
        includeAll: actor?.role === 'admin',
      },
    });
    const target = existing.find((item: any) => item.id === entryId);

    if (!target) {
      res.status(404).json({ message: 'Vault entry not found' });
      return;
    }

    const encryptionKey = deriveEncryptionKey(process.env.VAULT_MASTER_SECRET ?? 'dev-master-secret');
    
    // Detect changed fields
    const changedFields = [];
    if (req.body.name && req.body.name !== target.name) changedFields.push('nombre');
    if (req.body.url && req.body.url !== target.url) changedFields.push('url');
    if (req.body.username && req.body.username !== target.username) changedFields.push('usuario');
    
    let isPasswordChanged = false;
    if (req.body.password) {
      try {
        const decryptedTarget = target.password ? decryptSecret(target.password, encryptionKey) : '';
        if (req.body.password !== decryptedTarget) {
          isPasswordChanged = true;
          changedFields.push('contraseña');
        }
      } catch (e) {
        // En caso de fallo al desencriptar, asumimos que cambió
        isPasswordChanged = true;
        changedFields.push('contraseña');
      }
    }

    if (req.body.notes !== undefined && req.body.notes !== target.notes) changedFields.push('notas');

    const updated = await prisma.vaultEntry.update({
      where: { id: entryId },
      data: {
        ...req.body,
        password: req.body.password ? encryptSecret(String(req.body.password), encryptionKey) : undefined,
        updatedAt: new Date().toISOString(),
      },
    });

    await createAuditLog(userId, 'vault_update', 'Vault entry updated', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId,
      changes: changedFields.length > 0 ? changedFields.join(', ') : 'ninguno',
    });

    res.json({
      item: {
        ...updated,
        password: req.body.password ? String(req.body.password) : decryptSecret(updated.password, deriveEncryptionKey(process.env.VAULT_MASTER_SECRET ?? 'dev-master-secret')),
      },
    });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Vault update failed' });
  }
});

app.delete('/vault/entries/:id', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const entryId = getRouteParam(req.params.id);

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    const existing = await prisma.vaultEntry.findMany({
      where: {
        userId: actor?.role === 'admin' ? undefined : userId,
        includeAll: actor?.role === 'admin',
      },
    });
    const target = existing.find((item: any) => item.id === entryId);

    if (!target) {
      res.status(404).json({ message: 'Vault entry not found' });
      return;
    }

    await prisma.vaultEntry.delete({ where: { id: entryId } });
    await createAuditLog(userId, 'vault_delete', 'Vault entry deleted', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId,
    });
    res.json({ message: 'Vault entry deleted' });
  } catch (error) {
    res.status(400).json({ message: error instanceof Error ? error.message : 'Vault deletion failed' });
  }
});

if (process.env.NODE_ENV !== 'test') {
  const port = process.env.PORT ? Number(process.env.PORT) : 4000;
  app.listen(port, () => {
    console.log(`API listening on port ${port}`);
  });
}

export { app };
