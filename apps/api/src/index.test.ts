import { beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { generate } from 'otplib';
import { app } from './index.js';
import { prisma } from './lib/prisma.js';

beforeEach(async () => {
  await prisma.auditLog.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.user.deleteMany();
});

describe('GET /health', () => {
  it('returns api health status', async () => {
    const response = await request(app).get('/health');

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: 'ok', service: 'api' });
  });
});

describe('Auth flow', () => {
  it('logs in the default local admin account when the credentials are used', async () => {
    const loginResponse = await request(app).post('/auth/login').send({
      email: 'info@gestiongroup.es',
      password: 'Gestion2026.',
    });

    expect(loginResponse.status).toBe(200);
    expect(loginResponse.body.user.email).toBe('info@gestiongroup.es');
    expect(loginResponse.body.user.role).toBe('admin');
  });

  it('registers and logs in a user', async () => {
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'admin@empresa.test',
      password: 'Password123!',
    });

    expect(registerResponse.status).toBe(201);
    expect(registerResponse.body.user.email).toBe('admin@empresa.test');

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'admin@empresa.test',
      password: 'Password123!',
    });

    expect(loginResponse.status).toBe(200);
    expect(loginResponse.body.accessToken).toBeDefined();
    expect(loginResponse.body.refreshToken).toBeDefined();
  });

  it('returns the current authenticated user', async () => {
    await request(app).post('/auth/register').send({
      email: 'user@empresa.test',
      password: 'Password123!',
    });

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'user@empresa.test',
      password: 'Password123!',
    });

    const meResponse = await request(app)
      .get('/auth/me')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`);

    expect(meResponse.status).toBe(200);
    expect(meResponse.body.user.email).toBe('user@empresa.test');
  });

  it('refreshes tokens with a valid refresh token', async () => {
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'refresh@empresa.test',
      password: 'Password123!',
    });

    const refreshResponse = await request(app)
      .post('/auth/refresh')
      .set('x-refresh-token', registerResponse.body.refreshToken);

    expect(refreshResponse.status).toBe(200);
    expect(refreshResponse.body.accessToken).toBeDefined();
    expect(refreshResponse.body.refreshToken).toBeDefined();
  });
});

describe('MFA flow', () => {
  it('enables MFA and requires a valid code for subsequent logins', async () => {
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'mfa@empresa.test',
      password: 'Password123!',
    });

    const setupResponse = await request(app)
      .post('/auth/mfa/setup')
      .set('Authorization', `Bearer ${registerResponse.body.accessToken}`);

    expect(setupResponse.status).toBe(200);
    expect(setupResponse.body.secret).toBeDefined();

    const code = await generate({ secret: setupResponse.body.secret });

    const verifyResponse = await request(app)
      .post('/auth/mfa/verify')
      .set('Authorization', `Bearer ${registerResponse.body.accessToken}`)
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
    const adminRegister = await request(app).post('/auth/register').send({
      email: 'admin-user@empresa.test',
      password: 'Password123!',
      role: 'admin',
    });

    const adminLogin = await request(app).post('/auth/login').send({
      email: 'admin-user@empresa.test',
      password: 'Password123!',
    });

    const regularRegister = await request(app).post('/auth/register').send({
      email: 'regular-user@empresa.test',
      password: 'Password123!',
    });

    const listResponse = await request(app)
      .get('/admin/users')
      .set('Authorization', `Bearer ${adminLogin.body.accessToken}`);

    expect(listResponse.status).toBe(200);
    expect(listResponse.body.users).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ email: 'regular-user@empresa.test' }),
      ]),
    );

    const updateResponse = await request(app)
      .put(`/admin/users/${regularRegister.body.user.id}/role`)
      .set('Authorization', `Bearer ${adminLogin.body.accessToken}`)
      .send({ role: 'auditor' });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.body.user.role).toBe('auditor');
  });
});

describe('Audit log flow', () => {
  it('allows auditors to list audit events and blocks regular users', async () => {
    await request(app).post('/auth/register').send({
      email: 'audit@empresa.test',
      password: 'Password123!',
      role: 'auditor',
    });

    const regularUserResponse = await request(app).post('/auth/register').send({
      email: 'user-audit@empresa.test',
      password: 'Password123!',
    });

    const auditorLogin = await request(app).post('/auth/login').send({
      email: 'audit@empresa.test',
      password: 'Password123!',
    });

    const regularLogin = await request(app).post('/auth/login').send({
      email: 'user-audit@empresa.test',
      password: 'Password123!',
    });

    const blockedResponse = await request(app)
      .get('/audit/logs')
      .set('Authorization', `Bearer ${regularLogin.body.accessToken}`);

    expect(blockedResponse.status).toBe(403);

    const auditResponse = await request(app)
      .get('/audit/logs')
      .set('Authorization', `Bearer ${auditorLogin.body.accessToken}`);

    expect(auditResponse.status).toBe(200);
    expect(auditResponse.body.logs.length).toBeGreaterThan(0);
    expect(auditResponse.body.logs[0]).toMatchObject({
      userId: regularUserResponse.body.user.id,
    });
  });
});

describe('Vault flow', () => {
  it('creates and lists vault entries for an authenticated user', async () => {
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'vault@empresa.test',
      password: 'Password123!',
    });

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'vault@empresa.test',
      password: 'Password123!',
    });

    const createResponse = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .send({
        name: 'Producción DB',
        url: 'https://db.empresa.test',
        username: 'appuser',
        password: 'SuperSecret123!',
        notes: 'Credencial de base de datos',
      });

    expect(createResponse.status).toBe(201);
    expect(createResponse.body.item.password).toBe('SuperSecret123!');

    const listResponse = await request(app)
      .get('/vault/entries')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`);

    expect(listResponse.status).toBe(200);
    expect(listResponse.body.items).toHaveLength(1);
    expect(listResponse.body.items[0].name).toBe('Producción DB');
  });

  it('filters vault entries by search text', async () => {
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'vault-search@empresa.test',
      password: 'Password123!',
    });

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'vault-search@empresa.test',
      password: 'Password123!',
    });

    await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .send({
        name: 'Correo corporativo',
        url: 'https://mail.empresa.test',
        username: 'jdoe',
        password: 'OldPassword123!',
      });

    await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .send({
        name: 'Base de datos',
        url: 'https://db.empresa.test',
        username: 'appuser',
        password: 'SuperSecret123!',
      });

    const searchResponse = await request(app)
      .get('/vault/entries?search=mail')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`);

    expect(searchResponse.status).toBe(200);
    expect(searchResponse.body.items).toHaveLength(1);
    expect(searchResponse.body.items[0].name).toBe('Correo corporativo');
  });

  it('allows admins to view all vault entries and share them with other users', async () => {
    const adminRegister = await request(app).post('/auth/register').send({
      email: 'vault-admin@empresa.test',
      password: 'Password123!',
      role: 'admin',
    });

    const adminLogin = await request(app).post('/auth/login').send({
      email: 'vault-admin@empresa.test',
      password: 'Password123!',
    });

    const userRegister = await request(app).post('/auth/register').send({
      email: 'vault-shared@empresa.test',
      password: 'Password123!',
    });

    const userLogin = await request(app).post('/auth/login').send({
      email: 'vault-shared@empresa.test',
      password: 'Password123!',
    });

    const created = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${userLogin.body.accessToken}`)
      .send({
        name: 'Portal interno',
        url: 'https://intranet.test',
        username: 'ops',
        password: 'SharedPassword123!',
      });

    const adminListResponse = await request(app)
      .get('/vault/entries')
      .set('Authorization', `Bearer ${adminLogin.body.accessToken}`);

    expect(adminListResponse.status).toBe(200);
    expect(adminListResponse.body.items).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: created.body.item.id })]),
    );

    const shareResponse = await request(app)
      .post(`/vault/entries/${created.body.item.id}/shares`)
      .set('Authorization', `Bearer ${adminLogin.body.accessToken}`)
      .send({ userId: userRegister.body.user.id });

    expect(shareResponse.status).toBe(201);

    const sharedListResponse = await request(app)
      .get('/vault/entries')
      .set('Authorization', `Bearer ${userLogin.body.accessToken}`);

    expect(sharedListResponse.status).toBe(200);
    expect(sharedListResponse.body.items).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: created.body.item.id })]),
    );
  });

  it('updates and deletes vault entries for the authenticated user', async () => {
    const registerResponse = await request(app).post('/auth/register').send({
      email: 'vault-edit@empresa.test',
      password: 'Password123!',
    });

    const loginResponse = await request(app).post('/auth/login').send({
      email: 'vault-edit@empresa.test',
      password: 'Password123!',
    });

    const created = await request(app)
      .post('/vault/entries')
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .send({
        name: 'Correo corporativo',
        url: 'https://mail.empresa.test',
        username: 'jdoe',
        password: 'OldPassword123!',
      });

    const updateResponse = await request(app)
      .put(`/vault/entries/${created.body.item.id}`)
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`)
      .send({
        name: 'Correo corporativo actualizado',
        password: 'NewPassword456!',
      });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.body.item.name).toBe('Correo corporativo actualizado');
    expect(updateResponse.body.item.password).toBe('NewPassword456!');

    const deleteResponse = await request(app)
      .delete(`/vault/entries/${created.body.item.id}`)
      .set('Authorization', `Bearer ${loginResponse.body.accessToken}`);

    expect(deleteResponse.status).toBe(200);
    expect(deleteResponse.body.message).toBe('Vault entry deleted');
  });
});
