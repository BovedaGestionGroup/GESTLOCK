import express from 'express';
import { randomBytes, scryptSync, createCipheriv } from 'crypto';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import XlsxPopulate from 'xlsx-populate';
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
import { sendVerificationEmail, sendPasswordResetEmail, sendAdminResetNotificationEmail } from './email.js';
import { prisma } from './lib/prisma.js';
import { requireEnv } from './lib/requireEnv.js';

// ─── Carga de variables de entorno ───────────────────────────────────────────
dotenv.config();

// ─── Validación de secretos obligatorios al arrancar ─────────────────────────
// [C-01] Si alguno de estos secretos no está configurado, la app NO arranca.
// Esto evita que se use en producción con valores por defecto inseguros.
if (process.env.NODE_ENV === 'production') {
  requireEnv('JWT_SECRET');
  requireEnv('JWT_REFRESH_SECRET');
  requireEnv('VAULT_MASTER_SECRET');
  // [A-05] En producción, debe haber proveedor de email configurado
  if (!process.env.RESEND_API_KEY && !(process.env.SMTP_USER && process.env.SMTP_PASS)) {
    throw new Error(
      '[STARTUP ERROR] No email provider configured in production. ' +
        'Set RESEND_API_KEY or SMTP_USER + SMTP_PASS environment variables.',
    );
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

async function createAuditLog(
  userId: string | undefined,
  action: string,
  details: string,
  metadata?: Record<string, string | undefined>,
) {
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
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/** Clave de cifrado de bóveda — derivada dinámicamente con userSalt [C-03] */
function getVaultKey(userSalt?: string | null): Buffer {
  return deriveEncryptionKey(requireEnv('VAULT_MASTER_SECRET'), userSalt ?? undefined);
}

/** Mapeo de errores internos a mensajes seguros para el cliente [M-02] */
function safeErrorMessage(error: unknown, fallback: string): string {
  // Solo devolver el mensaje interno si es un error de validación de Zod (no contiene info de BD)
  if (error instanceof Error && error.message.startsWith('Invalid')) {
    return error.message;
  }
  return fallback;
}

// ─── App Express ──────────────────────────────────────────────────────────────

const app = express();

// [C-04] CORS restringido a orígenes de confianza explícitos.
// Nunca usar origin:true con credentials:true (refleja cualquier origen).
const configuredFrontend = process.env.FRONTEND_URL || 'https://gestor-web-ikec.onrender.com';
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? [
      configuredFrontend,
      'https://gestor-web-ikec.onrender.com',
      'https://gestor-web.onrender.com',
    ]
  : ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:4000'];

const isAllowedOrigin = (origin: string): boolean => {
  if (allowedOrigins.includes(origin)) return true;
  if (/^https:\/\/gestor-web-[a-z0-9]+\.onrender\.com$/.test(origin)) return true;
  return false;
};

app.use(
  cors({
    origin: (origin, callback) => {
      // Permitir peticiones sin Origin (Postman, curl en desarrollo)
      if (!origin) return callback(null, true);
      if (isAllowedOrigin(origin)) {
        callback(null, true);
      } else {
        callback(null, false);
      }
    },
    credentials: true,
  }),
);

app.use(cookieParser());
app.use(express.json());

// ─── Cabeceras de seguridad ───────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0'); // Obsoleta; desactivada intencionalmente (ver B-01)

  // [A-06] HSTS — solo en producción (detrás de HTTPS de Render)
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }

  // [A-06] CSP dinámica según entorno — sin localhost en producción
  const requestOrigin = req.headers.origin;
  const validOriginForCsp = requestOrigin && isAllowedOrigin(requestOrigin) ? requestOrigin : configuredFrontend;
  const connectSrc = process.env.NODE_ENV === 'production'
    ? `'self' ${validOriginForCsp} https://gestor-web-ikec.onrender.com https://gestor-web.onrender.com`
    : "'self' http://localhost:3000 http://localhost:4000";

  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src ${connectSrc}`,
  );

  next();
});

// ─── Rate limiting [A-03] ─────────────────────────────────────────────────────

/** Límite general de autenticación: 20 intentos / 15 min por IP */
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'test',
  message: { message: 'Demasiados intentos. Espera 15 minutos antes de volver a intentarlo.' },
});

/** Límite estricto para MFA: 5 intentos / 15 min por IP */
const mfaRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  skip: () => process.env.NODE_ENV === 'test',
  message: { message: 'Demasiados intentos de MFA. Espera 15 minutos.' },
});

// ─── Rutas públicas ───────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'api' });
});

app.post('/auth/register', authRateLimit, async (req, res) => {
  try {
    const parsed = registerSchema.parse(req.body);
    const requestedRole = typeof req.body.role === 'string' ? req.body.role : 'user';
    const code = generateVerificationCode();
    await registerUser(parsed.email, parsed.password, requestedRole, code);

    // [A-02] Respuesta genérica: no revelar si el email ya existía o no
    try {
      const user = await prisma.user.findUnique({ where: { email: parsed.email.trim().toLowerCase() } });
      if (user) await sendVerificationEmail(user.email, code);
    } catch (emailError) {
      console.error('[AUTH] Failed to send verification email:', emailError instanceof Error ? emailError.message : emailError);
    }

    // [A-02] Mismo mensaje tanto si el usuario existía como si es nuevo
    res.status(201).json({ message: 'Si los datos son correctos, recibirás un correo de verificación.' });
  } catch (error) {
    // No exponer si es un error de "usuario ya existe" u otro
    res.status(400).json({ message: 'No se pudo completar el registro. Revisa los datos e inténtalo de nuevo.' });
  }
});

app.post('/auth/verify-email', authRateLimit, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) {
      res.status(400).json({ message: 'Email y código son requeridos' });
      return;
    }
    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase().trim() } });

    // [A-02] No revelar si el usuario existe o si el email ya está verificado
    if (!user || user.isVerified || user.verificationCode !== code) {
      res.status(400).json({ message: 'Código de verificación inválido o ya utilizado.' });
      return;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, verificationCode: null },
    });

    const accessToken = signAccessToken(user.id);
    const refreshToken = await createRefreshToken(user.id);

    await createAuditLog(user.id, 'verify_email', 'User verified email and logged in', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
    });

    res.json({
      message: 'Email verificado correctamente',
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled,
      },
    });
  } catch (error) {
    res.status(500).json({ message: 'Error al verificar el email. Inténtalo de nuevo.' });
  }
});

app.post('/auth/login', authRateLimit, async (req, res) => {
  try {
    const parsed = loginSchema.parse(req.body);
    const user = await authenticateUser(parsed.email, parsed.password);
    const code = typeof req.body.code === 'string' ? req.body.code : undefined;

    if (user.isActive === false) {
      res.status(403).json({ message: 'Cuenta desactivada. Contacta con el administrador.' });
      return;
    }

    if (!user.isVerified) {
      res.status(403).json({ message: 'Email no verificado. Revisa tu bandeja de entrada.' });
      return;
    }

    if (user.mfaEnabled) {
      if (!user.mfaSecret || !code || !(await verifyMfaCode(user.mfaSecret, code))) {
        res.status(401).json({ message: 'Código MFA requerido o inválido' });
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
    res.status(401).json({ message: 'Credenciales inválidas' });
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
      res.status(404).json({ message: 'Usuario no encontrado' });
      return;
    }

    const secret = generateMfaSecret();
    res.json({
      secret,
      otpauthUrl: `otpauth://totp/Gestor%20Contraseñas%20Empresarial:${encodeURIComponent(user.email)}?secret=${secret}&issuer=Gestor%20Contraseñas%20Empresarial`,
    });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo configurar MFA' });
  }
});

app.post('/auth/mfa/verify', authMiddleware, mfaRateLimit, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const code = typeof req.body.code === 'string' ? req.body.code : undefined;
    const secret = typeof req.body.secret === 'string' ? req.body.secret : undefined;

    if (!code || !secret || !(await verifyMfaCode(secret, code))) {
      res.status(401).json({ message: 'Código MFA inválido' });
      return;
    }

    await prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true, mfaSecret: secret },
    });

    res.json({ message: 'MFA activado correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo verificar MFA' });
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
      res.status(404).json({ message: 'Usuario no encontrado' });
      return;
    }
    res.json({ user: { id: user.id, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo cargar el usuario' });
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
    res.status(500).json({ message: 'No se pudieron cargar los logs de auditoría' });
  }
});

// ─── Admin: Usuarios ──────────────────────────────────────────────────────────

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

    const search = typeof req.query.search === 'string' ? req.query.search.trim() : undefined;
    const whereCondition = search
      ? {
          OR: [
            { email: { contains: search, mode: 'insensitive' as const } },
            { role: { contains: search, mode: 'insensitive' as const } },
          ],
        }
      : undefined;

    const users = await prisma.user.findMany({
      where: whereCondition,
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
    res.status(500).json({ message: 'No se pudo listar los usuarios' });
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
    // [Fase 5] Reasignar las entradas corporativas al administrador antes de eliminar el usuario
    await prisma.vaultEntry.updateMany({
      where: { userId: targetId },
      data: { userId: actor.id },
    });

    await prisma.user.delete({ where: { id: targetId } });
    await createAuditLog(userId, 'admin_delete_user', 'User deleted and vault entries preserved/reassigned to admin', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
    });
    res.json({ message: 'Usuario eliminado y sus entradas de bóveda fueron preservadas y reasignadas al administrador.' });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo eliminar el usuario' });
  }
});

app.put('/admin/users/:id/status', authMiddleware, async (req, res) => {
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
    const { isActive } = req.body;
    if (typeof isActive !== 'boolean') {
      res.status(400).json({ message: 'El campo isActive es requerido' });
      return;
    }
    const updated = await prisma.user.update({
      where: { id: targetId },
      data: { isActive },
    });
    await createAuditLog(userId, 'admin_update_user_status', `User status updated to ${isActive ? 'activo' : 'desactivado'}`, {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
    });
    res.json({ user: updated });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo actualizar el estado del usuario' });
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
    res.json({ message: 'Usuario verificado' });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo verificar el usuario' });
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
      res.status(404).json({ message: 'Usuario no encontrado' });
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
    // [A-04] Token en fragmento de URL (#) — no viaja al servidor ni aparece en logs de proxy/CDN
    const resetUrl = `${appUrl}#resetToken=${token}&email=${encodeURIComponent(target.email)}`;
    await sendPasswordResetEmail(target.email, resetUrl);
    await createAuditLog(userId, 'admin_send_reset_password', 'Password reset sent', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
    });
    res.json({ message: `Email de recuperación enviado a ${target.email}` });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo enviar el email de recuperación' });
  }
});

app.post('/auth/reset-password', authRateLimit, async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    if (!token || !email || !newPassword) {
      res.status(400).json({ message: 'Token, email y nueva contraseña son requeridos' });
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
      res.status(400).json({ message: 'Datos inválidos' });
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
    res.status(500).json({ message: 'No se pudo restablecer la contraseña' });
  }
});

// ─── Protocolo de Recuperación con Aprobación del Admin (Fase 4) ──────────────

app.post('/auth/forgot-password', authRateLimit, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') {
      res.status(400).json({ message: 'El correo electrónico es requerido' });
      return;
    }
    const normalizedEmail = email.toLowerCase().trim();
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (user) {
      if (user.role === 'admin') {
        const token = randomBytes(32).toString('hex');
        await prisma.passwordResetToken.create({
          data: {
            token,
            userId: user.id,
            expiresAt: new Date(Date.now() + 60 * 60 * 1000),
          },
        });
        const appUrl = process.env.APP_URL || 'http://localhost:3000';
        const resetUrl = `${appUrl}#resetToken=${token}&email=${encodeURIComponent(user.email)}`;
        await sendPasswordResetEmail(user.email, resetUrl);
        await createAuditLog(user.id, 'admin_direct_password_reset', 'Admin requested password reset', {
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
        });
      } else {
        const existing = await prisma.passwordResetRequest.findMany({
          where: { userId: user.id, status: 'PENDING' },
        });
        if (existing.length === 0) {
          await prisma.passwordResetRequest.create({
            data: { userId: user.id, status: 'PENDING' },
          });
          await createAuditLog(user.id, 'forgot_password_request', 'Password reset requested by user', {
            ipAddress: req.ip,
            userAgent: req.get('user-agent'),
          });
        }
        await sendAdminResetNotificationEmail(user.email);
      }
    }
    res.json({ message: 'Si el correo está registrado, se ha enviado la solicitud de restablecimiento para revisión del administrador.' });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo procesar la solicitud' });
  }
});


app.get('/admin/password-requests', authMiddleware, async (req, res) => {
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
    const requests = await prisma.passwordResetRequest.findMany({
      where: { status: 'PENDING' },
      include: {
        user: {
          select: { id: true, email: true, role: true, createdAt: true },
        },
      },
      orderBy: { requestedAt: 'desc' },
    });
    res.json({ requests });
  } catch (error) {
    res.status(500).json({ message: 'No se pudieron consultar las solicitudes' });
  }
});

app.post('/admin/password-requests/:id/approve', authMiddleware, async (req, res) => {
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
    const requestId = getRouteParam(req.params.id);
    const resetReq = await prisma.passwordResetRequest.findUnique({ where: { id: requestId } });
    if (!resetReq || resetReq.status !== 'PENDING') {
      res.status(404).json({ message: 'Solicitud no encontrada o ya procesada' });
      return;
    }
    const targetUser = await prisma.user.findUnique({ where: { id: resetReq.userId } });
    if (!targetUser) {
      res.status(404).json({ message: 'Usuario no encontrado' });
      return;
    }

    const token = randomBytes(32).toString('hex');
    await prisma.passwordResetToken.create({
      data: {
        token,
        userId: targetUser.id,
        expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      },
    });
    await prisma.passwordResetRequest.update({
      where: { id: requestId },
      data: { status: 'APPROVED', reviewedAt: new Date(), token },
    });

    const appUrl = process.env.APP_URL || 'http://localhost:3000';
    const resetUrl = `${appUrl}#resetToken=${token}&email=${encodeURIComponent(targetUser.email)}`;
    await sendPasswordResetEmail(targetUser.email, resetUrl);
    await createAuditLog(userId, 'password_reset_approved', `Approved password reset for ${targetUser.email}`, {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetUser.id,
      requestId,
    });

    res.json({ message: `Solicitud aprobada y correo enviado a ${targetUser.email}` });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo aprobar la solicitud' });
  }
});

app.post('/admin/password-requests/:id/reject', authMiddleware, async (req, res) => {
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
    const requestId = getRouteParam(req.params.id);
    const resetReq = await prisma.passwordResetRequest.findUnique({ where: { id: requestId } });
    if (!resetReq || resetReq.status !== 'PENDING') {
      res.status(404).json({ message: 'Solicitud no encontrada o ya procesada' });
      return;
    }

    await prisma.passwordResetRequest.update({
      where: { id: requestId },
      data: { status: 'REJECTED', reviewedAt: new Date() },
    });
    await createAuditLog(userId, 'password_reset_rejected', `Rejected password reset request`, {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      requestId,
    });

    res.json({ message: 'Solicitud rechazada' });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo rechazar la solicitud' });
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
      res.status(400).json({ message: 'Rol inválido' });
      return;
    }

    const updatedUser = await prisma.user.update({
      where: { id: targetId },
      data: { role },
      select: { id: true, email: true, role: true },
    });

    await createAuditLog(userId, 'admin_role_update', 'Role updated', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      targetUserId: targetId,
      role,
    });

    res.json({ user: updatedUser });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo actualizar el rol' });
  }
});

// ─── Sesiones ─────────────────────────────────────────────────────────────────

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
    res.json({ message: 'Sesión cerrada correctamente' });
  } catch (error) {
    res.status(500).json({ message: 'Error al cerrar sesión' });
  }
});

app.post('/auth/refresh', authRateLimit, async (req, res) => {
  try {
    const refreshToken =
      typeof req.headers['x-refresh-token'] === 'string' && req.headers['x-refresh-token']
        ? req.headers['x-refresh-token']
        : req.cookies?.refreshToken;
    if (typeof refreshToken !== 'string' || refreshToken.length === 0) {
      res.status(401).json({ message: 'Refresh token requerido' });
      return;
    }
    const userId = await verifyRefreshToken(refreshToken);
    const accessToken = signAccessToken(userId);
    const nextRefreshToken = await createRefreshToken(userId);
    res.json({ accessToken, refreshToken: nextRefreshToken });
  } catch (error) {
    res.status(401).json({ message: 'Sesión expirada. Por favor, inicia sesión de nuevo.' });
  }
});

// ─── Bóveda ───────────────────────────────────────────────────────────────────

app.post('/vault/entries', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    // [C-03] Obtener userSalt único del propietario para derivar la clave de cifrado
    const user = await prisma.user.findUnique({ where: { id: userId } });
    const encryptionKey = getVaultKey(user?.userSalt);
    const encryptedPassword = encryptSecret(String(req.body.password ?? ''), encryptionKey);

    const item = {
      id: `entry-${Date.now()}`,
      userId,
      name: req.body.name,
      url: req.body.url,
      username: req.body.username,
      password: encryptedPassword,
      notes: req.body.notes,
      createdAt: new Date(),
    };

    await prisma.vaultEntry.create({ data: item });

    await createAuditLog(userId, 'vault_create', 'Vault entry created', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId: item.id,
    });

    // Devolver la entrada sin la contraseña cifrada (la contraseña en claro solo se devuelve aquí)
    res.status(201).json({
      item: {
        ...item,
        password: String(req.body.password ?? ''),
      },
    });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo crear la entrada en la bóveda' });
  }
});

// [A-01] GET /vault/entries — Solo devuelve METADATOS (sin contraseñas).
// Para ver la contraseña, usar GET /vault/entries/:id/reveal
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

    // [A-01] Nunca enviar contraseñas en el listado — solo metadatos
    const safeItems = items.map((entry: any) => ({
      id: entry.id,
      userId: entry.userId,
      name: entry.name,
      url: entry.url,
      username: entry.username,
      notes: entry.notes,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
      // password: OMITIDO intencionalmente
    }));

    res.json({ items: safeItems });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo cargar la bóveda' });
  }
});

// [A-01] Nuevo endpoint: revelar contraseña de UNA entrada con registro de auditoría
app.get('/vault/entries/:id/reveal', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    const entryId = getRouteParam(req.params.id);

    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    const entries = await prisma.vaultEntry.findMany({
      where: {
        userId: actor?.role === 'admin' ? undefined : actor?.id ?? userId,
        includeAll: actor?.role === 'admin',
      },
    });
    const entry = entries.find((e: any) => e.id === entryId);

    if (!entry) {
      res.status(404).json({ message: 'Entrada no encontrada' });
      return;
    }

    const owner = await prisma.user.findUnique({ where: { id: entry.userId } });
    const decryptedPassword = decryptSecret(entry.password, getVaultKey(owner?.userSalt));

    // [A-01] Registrar auditoría de visualización de contraseña
    await createAuditLog(userId, 'vault_view', 'Vault entry password revealed', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId,
    });

    res.json({ password: decryptedPassword });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo revelar la contraseña' });
  }
});

// ─── Exportación a Excel Cifrado (Fase 6) ────────────────────────────────────

app.post('/vault/export-excel', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }

    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || (!hasPermission(actor.role, 'admin') && !hasPermission(actor.role, 'auditor'))) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const items = await prisma.vaultEntry.findMany({
      where: {
        userId: actor.role === 'admin' || actor.role === 'auditor' ? undefined : actor.id ?? userId,
        includeAll: actor.role === 'admin' || actor.role === 'auditor',
      },
    });

    // 1. Determinar contraseña de cifrado del Excel
    // - Si el usuario envía una contraseña personalizada, se usa esa.
    // - Si se indica explícitamente sin contraseña (password: '' o null o encrypt: false), no se protege.
    // - Por defecto, si no se especifica, se genera una clave aleatoria segura de 16 caracteres.
    let exportPassword: string | undefined;
    if (typeof req.body?.password === 'string') {
      exportPassword = req.body.password.trim() || undefined;
    } else if (req.body?.password === null || req.body?.encrypt === false) {
      exportPassword = undefined;
    } else {
      exportPassword = randomBytes(8).toString('hex');
    }

    // 2. Construir libro Excel nativo (.xlsx)
    const workbook = await XlsxPopulate.fromBlankAsync();
    const sheet = workbook.sheet(0);
    sheet.name('Bóveda GESTLOCK');

    const headers = ['Nombre', 'URL', 'Usuario', 'Contraseña', 'Notas', 'Fecha de Creación'];
    headers.forEach((headerText, idx) => {
      const cell = sheet.row(1).cell(idx + 1);
      cell.value(headerText);
      cell.style({
        bold: true,
        fill: '0D9488',
        fontColor: 'FFFFFF',
        horizontalAlignment: 'center',
      });
    });

    sheet.column(1).width(25);
    sheet.column(2).width(35);
    sheet.column(3).width(25);
    sheet.column(4).width(25);
    sheet.column(5).width(40);
    sheet.column(6).width(24);

    let rowIndex = 2;
    for (const entry of items) {
      const owner = await prisma.user.findUnique({ where: { id: entry.userId } });
      const decryptedPassword = entry.password ? decryptSecret(entry.password, getVaultKey(owner?.userSalt)) : '';
      sheet.row(rowIndex).cell(1).value(entry.name || '');
      sheet.row(rowIndex).cell(2).value(entry.url || '');
      sheet.row(rowIndex).cell(3).value(entry.username || '');
      sheet.row(rowIndex).cell(4).value(decryptedPassword || '');
      sheet.row(rowIndex).cell(5).value(entry.notes ?? '');
      sheet.row(rowIndex).cell(6).value(new Date(entry.createdAt).toLocaleString('es-ES'));
      rowIndex++;
    }

    // 3. Generar buffer de archivo .xlsx protegido con contraseña (o estándar)
    let rawBuffer: Buffer;
    if (exportPassword) {
      rawBuffer = await workbook.outputAsync({ password: exportPassword });
    } else {
      rawBuffer = await workbook.outputAsync();
    }

    const fileBase64 = Buffer.from(rawBuffer).toString('base64');
    const dateStr = new Date().toISOString().split('T')[0];
    const filename = `boveda_gestlock_${dateStr}.xlsx`;
    const isEncrypted = Boolean(exportPassword);

    // 4. Registro de auditoría e historial con IP
    await createAuditLog(
      userId,
      'vault_export',
      `Exportadas ${items.length} entradas de bóveda a Excel ${isEncrypted ? 'cifrado con contraseña' : 'sin cifrar'}`,
      {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
      }
    );

    res.json({
      success: true,
      tempKey: exportPassword || null,
      fileData: fileBase64,
      fileBase64,
      filename,
      isEncrypted,
    });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo generar la exportación a Excel' });
  }
});

app.get('/admin/audit-logs/exports', authMiddleware, async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      res.status(401).json({ message: 'Unauthorized' });
      return;
    }
    const actor = await prisma.user.findUnique({ where: { id: userId } });
    if (!actor || (!hasPermission(actor.role, 'admin') && !hasPermission(actor.role, 'auditor'))) {
      res.status(403).json({ message: 'Forbidden' });
      return;
    }

    const exportLogs = await prisma.auditLog.findMany({
      where: { action: 'vault_export' },
      include: {
        user: {
          select: { id: true, email: true, role: true },
        },
      },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });

    res.json({ logs: exportLogs });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo cargar el historial de exportaciones' });
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
          contains: `"entryId":"${entryId}"`,
        },
      },
      include: { user: true },
      orderBy: { createdAt: 'desc' },
    });

    res.json({ logs });
  } catch (error) {
    res.status(500).json({ message: 'No se pudo cargar el historial' });
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

    if (!targetUserId) {
      res.status(400).json({ message: 'El usuario destino es requerido' });
      return;
    }

    // Cargar la entrada primero para verificar propiedad
    const entry = await prisma.vaultEntry.findUnique({ where: { id: entryId } });
    const targetUser = await prisma.user.findUnique({ where: { id: targetUserId } });

    if (!entry || !targetUser) {
      res.status(404).json({ message: 'Entrada o usuario no encontrado' });
      return;
    }

    // [IDOR fix] Comparar con entry.userId (dueño real de la entrada), no con userId del actor
    if (!actor || (!hasPermission(actor.role, 'admin') && actor.id !== entry.userId)) {
      res.status(403).json({ message: 'Solo el propietario de la entrada o un administrador puede compartirla' });
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
    res.status(400).json({ message: 'No se pudo compartir la entrada' });
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
      res.status(404).json({ message: 'Entrada no encontrada' });
      return;
    }

    const owner = await prisma.user.findUnique({ where: { id: target.userId } });
    const encryptionKey = getVaultKey(owner?.userSalt);

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

    // [A-01] No devolver la contraseña descifrada en la actualización
    const { password: _omit, ...updatedWithoutPassword } = updated as any;
    res.json({ item: updatedWithoutPassword });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo actualizar la entrada' });
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
      res.status(404).json({ message: 'Entrada no encontrada' });
      return;
    }

    await prisma.vaultEntry.delete({ where: { id: entryId } });
    await createAuditLog(userId, 'vault_delete', 'Vault entry deleted', {
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      entryId,
    });
    res.json({ message: 'Entrada eliminada' });
  } catch (error) {
    res.status(400).json({ message: 'No se pudo eliminar la entrada' });
  }
});

// ─── Arranque ─────────────────────────────────────────────────────────────────

if (process.env.NODE_ENV !== 'test') {
  const port = process.env.PORT ? Number(process.env.PORT) : 4000;
  const server = app.listen(port, () => {
    console.log(`API listening on port ${port}`);
  });

  // Cortar conexiones que no respondan en 30s para evitar acumulación en el cliente
  server.setTimeout(30_000);
  server.keepAliveTimeout = 65_000; // > 60s de Render para evitar 502 por keepalive
  server.headersTimeout = 66_000;
}

export { app };
