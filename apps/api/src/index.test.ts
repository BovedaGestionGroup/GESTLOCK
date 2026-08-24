import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { generate } from 'otplib';
import { app } from './index.js';
import { prisma } from './lib/prisma.js';
import { registerUser } from './auth.js';

beforeEach(async () => {
  await prisma.auditLog.deleteMany();
  await prisma.vaultEntryShare.deleteMany();
  await prisma.vaultEntry.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.user.deleteMany();
});

// Helper para crear un usuario verificado directamente en BD y obtener sus tokens
async function createVerifiedUserAndLogin(email: string, password: string, role = 'user') {
  await registerUser(email, password, role, undefined, true);
  const loginResponse = await request(app).post('/auth/login').send({ email, password });
  return loginResponse.body;
}

describe('GET /health', () => {
  it('returns api health status', async () => {
    const response = await request(app).get('/health');
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok', service: 'api' });
  });
});

describe('Auth flow', () => {
  // [C-02] El auto-aprovisionamiento del admin por defecto ha sido eliminado.
  // La cuenta inicial se crea mediante el script seed-admin.mjs.
  it('rejects login with the old default admin credentials (C-02 fixed)', async () => {
    const loginResponse = await request(app).post('/auth/login').send({
      email: 'info@gestiongroup.es',
      password: 'Gestion2026.',
    });
    // Ahora debe devolver 401 porque no existe esa cuenta por defecto
    expect(loginResponse.status).toBe(401);
  });

  it('registers and logs in a verified user', async () => {
    // Registro — el endpoint ahora devuelve mensaje genérico [A-02]
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'testuser@empresa.test',
      password: 'Password123!',
    });
    expect(registerResponse.status).toBe(201);

    // Verificar el email directamente en BD (simular el flujo de verificación)
    const user = await prisma.user.findUnique({ where: { email: 'testuser@empresa.test' } });
    if (user) {
      await prisma.user.update({ where: { id: user.id }, data: { isVerified: true, verificationCode: null } });
    }

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'testuser@empresa.test',
      password: 'Password123!',
    });

    expect(loginResponse.status).toBe(200);
    expect(loginResponse.body.accessToken).toBeDefined();
    expect(loginResponse.body.refreshToken).toBeDefined();
  });

  it('returns 401 for invalid credentials', async () => {
    const loginResponse = await request(app).post('/auth/login').send({
      email: 'noexiste@empresa.test',
      password: 'Password123!',
    });
    expect(loginResponse.status).toBe(401);
    // [M-02] El mensaje no debe revelar detalles internos
    expect(loginResponse.body.message).toBe('Credenciales inválidas');
  });

  it('returns the current authenticated user', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('me@empresa.test', 'Password123!');

    const meResponse = await request(app)
      .get('/auth/me')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(meResponse.status).toBe(200);
    expect(meResponse.body.user.email).toBe('me@empresa.test');
  });

  it('refreshes tokens with a valid refresh token', async () => {
    const { refreshToken } = await createVerifiedUserAndLogin('refresh@empresa.test', 'Password123!');

    const refreshResponse = await request(app)
      .post('/auth/refresh')
      .set('x-refresh-token', refreshToken);

    expect(refreshResponse.status).toBe(200);
    expect(refreshResponse.body.accessToken).toBeDefined();
    expect(refreshResponse.body.refreshToken).toBeDefined();
  });

  it('blocks login for unverified users', async () => {
    await request(app).post('/auth/register').send({
      email: 'unverified@empresa.test',
      password: 'Password123!',
    });

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'unverified@empresa.test',
      password: 'Password123!',
    });

    expect(loginResponse.status).toBe(403);
  });
});

describe('MFA flow', () => {
  it('enables MFA and requires a valid code for subsequent logins', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('mfa@empresa.test', 'Password123!');

    const setupResponse = await request(app)
      .post('/auth/mfa/setup')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(setupResponse.status).toBe(200);
    expect(setupResponse.body.secret).toBeDefined();

    const code = await generate({ secret: setupResponse.body.secret });

    const verifyResponse = await request(app)
      .post('/auth/mfa/verify')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ code, secret: setupResponse.body.secret });

    expect(verifyResponse.status).toBe(200);

    const loginWithoutCode = await request(app).post('/auth/login').send({
      email: 'mfa@empresa.test',
      password: 'Password123!',
    });
    expect(loginWithoutCode.status).toBe(401);

    const loginWithCode = await request(app).post('/auth/login').send({
      email: 'mfa@empresa.test',
      password: 'Password123!',
      code,
    });
    expect(loginWithCode.status).toBe(200);
    expect(loginWithCode.body.accessToken).toBeDefined();
  });
});

describe('Admin user management', () => {
  it('allows admins to list users and update roles', async () => {
    const { accessToken: adminToken } = await createVerifiedUserAndLogin('admin@empresa.test', 'Password123!', 'admin');
    await createVerifiedUserAndLogin('regular@empresa.test', 'Password123!', 'user');

    const listResponse = await request(app)
      .get('/admin/users')
      .set('Authorization', `Bearer ${adminToken}`);

    expect(listResponse.status).toBe(200);
    expect(listResponse.body.users).toEqual(
      expect.arrayContaining([expect.objectContaining({ email: 'regular@empresa.test' })]),
    );

    const regularUser = listResponse.body.users.find((u: any) => u.email === 'regular@empresa.test');

    const updateResponse = await request(app)
      .put(`/admin/users/${regularUser.id}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: 'auditor' });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.body.user.role).toBe('auditor');
  });

  it('blocks non-admins from accessing admin endpoints', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('user@empresa.test', 'Password123!', 'user');

    const listResponse = await request(app)
      .get('/admin/users')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(listResponse.status).toBe(403);
  });
});

describe('Audit log flow', () => {
  it('allows auditors to list audit events and blocks regular users', async () => {
    const { accessToken: auditorToken } = await createVerifiedUserAndLogin('auditor@empresa.test', 'Password123!', 'auditor');
    const { accessToken: userToken } = await createVerifiedUserAndLogin('user-audit@empresa.test', 'Password123!', 'user');

    const blockedResponse = await request(app)
      .get('/audit/logs')
      .set('Authorization', `Bearer ${userToken}`);
    expect(blockedResponse.status).toBe(403);

    const auditResponse = await request(app)
      .get('/audit/logs')
      .set('Authorization', `Bearer ${auditorToken}`);
    expect(auditResponse.status).toBe(200);
    expect(auditResponse.body.logs.length).toBeGreaterThan(0);
  });
});

describe('Vault flow', () => {
  it('creates and lists vault entries — listing does NOT include passwords [A-01]', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('vault@empresa.test', 'Password123!');

    const createResponse = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        name: 'Producción DB',
        url: 'https://db.empresa.test',
        username: 'appuser',
        password: 'SuperSecret123!',
        notes: 'Credencial de base de datos',
      });

    expect(createResponse.status).toBe(201);
    // La contraseña se devuelve al crear (solo en este momento)
    expect(createResponse.body.item.password).toBe('SuperSecret123!');

    const listResponse = await request(app)
      .get('/vault/entries')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(listResponse.status).toBe(200);
    expect(listResponse.body.items).toHaveLength(1);
    expect(listResponse.body.items[0].name).toBe('Producción DB');
    // [A-01] Las contraseñas NO se deben incluir en el listado
    expect(listResponse.body.items[0].password).toBeUndefined();
  });

  it('reveals password via /reveal endpoint and registers vault_view audit log [A-01]', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('reveal@empresa.test', 'Password123!');

    const createResponse = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        name: 'Entrada secreta',
        url: 'https://secret.test',
        username: 'user',
        password: 'MyRealPassword99!',
      });

    const entryId = createResponse.body.item.id;

    const revealResponse = await request(app)
      .get(`/vault/entries/${entryId}/reveal`)
      .set('Authorization', `Bearer ${accessToken}`);

    expect(revealResponse.status).toBe(200);
    expect(revealResponse.body.password).toBe('MyRealPassword99!');

    // Verificar que se creó el log de auditoría
    const auditLogs = await prisma.auditLog.findMany({ where: { action: 'vault_view' } });
    expect(auditLogs.length).toBeGreaterThan(0);
  });

  it('prevents sharing vault entries that you do not own [IDOR fix]', async () => {
    const { accessToken: ownerToken } = await createVerifiedUserAndLogin('owner@empresa.test', 'Password123!');
    const { accessToken: attackerToken } = await createVerifiedUserAndLogin('attacker@empresa.test', 'Password123!');
    const { accessToken: victimToken } = await createVerifiedUserAndLogin('victim@empresa.test', 'Password123!');

    // El dueño crea una entrada
    const created = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ name: 'Private entry', url: 'https://private.test', username: 'me', password: 'Private123456!' });

    const entryId = created.body.item.id;
    const victimUser = await prisma.user.findUnique({ where: { email: 'victim@empresa.test' } });

    // El atacante intenta compartir una entrada ajena
    const shareResponse = await request(app)
      .post(`/vault/entries/${entryId}/shares`)
      .set('Authorization', `Bearer ${attackerToken}`)
      .send({ userId: victimUser?.id });

    // Debe ser rechazado con 403
    expect(shareResponse.status).toBe(403);
  });

  it('filters vault entries by search text', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('search@empresa.test', 'Password123!');

    await request(app).post('/vault/entries').set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Correo corporativo', url: 'https://mail.empresa.test', username: 'jdoe', password: 'OldPassword123!' });

    await request(app).post('/vault/entries').set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Base de datos', url: 'https://db.empresa.test', username: 'appuser', password: 'SuperSecret123!' });

    const searchResponse = await request(app)
      .get('/vault/entries?search=mail')
      .set('Authorization', `Bearer ${accessToken}`);

    expect(searchResponse.status).toBe(200);
    expect(searchResponse.body.items).toHaveLength(1);
    expect(searchResponse.body.items[0].name).toBe('Correo corporativo');
  });

  it('updates vault entries correctly', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('edit@empresa.test', 'Password123!');

    const created = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Correo', url: 'https://mail.test', username: 'jdoe', password: 'OldPassword123!' });

    const updateResponse = await request(app)
      .put(`/vault/entries/${created.body.item.id}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Correo actualizado', password: 'NewPassword456!' });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.body.item.name).toBe('Correo actualizado');
    // [A-01] La respuesta de update ya no devuelve la contraseña en claro
    expect(updateResponse.body.item.password).toBeUndefined();
  });

  it('deletes vault entries correctly', async () => {
    const { accessToken } = await createVerifiedUserAndLogin('delete@empresa.test', 'Password123!');

    const created = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Para borrar', url: 'https://x.test', username: 'x', password: 'DeleteMe123456!' });

    const deleteResponse = await request(app)
      .delete(`/vault/entries/${created.body.item.id}`)
      .set('Authorization', `Bearer ${accessToken}`);

    expect(deleteResponse.status).toBe(200);
    expect(deleteResponse.body.message).toBe('Entrada eliminada');
  });
});
