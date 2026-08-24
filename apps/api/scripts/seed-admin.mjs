#!/usr/bin/env node
/**
 * GESTLOCK — Script de seed seguro para crear el primer administrador
 *
 * Uso (ejecutar UNA SOLA VEZ desde la raíz del proyecto):
 *   node apps/api/scripts/seed-admin.mjs
 *
 * El script genera una contraseña aleatoria fuerte y la muestra por consola
 * UNA SOLA VEZ. Guárdala inmediatamente en un lugar seguro.
 *
 * Variables de entorno requeridas:
 *   DATABASE_URL       — Cadena de conexión a PostgreSQL
 *   ADMIN_EMAIL        — Email del administrador a crear (o se pedirá por consola)
 *
 * Ejemplo con variables de entorno:
 *   ADMIN_EMAIL=admin@miempresa.com DATABASE_URL=postgres://... node apps/api/scripts/seed-admin.mjs
 */

import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import { randomBytes } from 'crypto';
import * as readline from 'readline';

const prisma = new PrismaClient();

function generateStrongPassword() {
  // Genera una contraseña de 24 caracteres con letras, números y símbolos
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
  const bytes = randomBytes(24);
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

async function askQuestion(prompt) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function main() {
  console.log('\n╔══════════════════════════════════════════════════╗');
  console.log('║   GESTLOCK — Creación del Administrador Inicial   ║');
  console.log('╚══════════════════════════════════════════════════╝\n');

  // Obtener email
  let adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail) {
    adminEmail = await askQuestion('Email del administrador: ');
  }

  if (!adminEmail || !adminEmail.includes('@')) {
    console.error('❌ Email inválido. Abortando.');
    process.exit(1);
  }

  // Comprobar si ya existe
  const existing = await prisma.user.findUnique({ where: { email: adminEmail.toLowerCase().trim() } });
  if (existing) {
    console.error(`❌ Ya existe un usuario con el email "${adminEmail}". Abortando para no sobreescribir.`);
    await prisma.$disconnect();
    process.exit(1);
  }

  // Generar contraseña segura
  const password = generateStrongPassword();
  const passwordHash = await argon2.hash(password);

  // Crear el usuario admin
  const admin = await prisma.user.create({
    data: {
      email: adminEmail.toLowerCase().trim(),
      passwordHash,
      role: 'admin',
      isVerified: true,
    },
  });

  console.log('\n✅ Administrador creado correctamente.\n');
  console.log('┌─────────────────────────────────────────────────────┐');
  console.log('│              CREDENCIALES DE ACCESO                 │');
  console.log('│  GUARDA ESTO EN UN LUGAR SEGURO AHORA MISMO        │');
  console.log('├─────────────────────────────────────────────────────┤');
  console.log(`│  Email:      ${admin.email.padEnd(38)}│`);
  console.log(`│  Contraseña: ${password.padEnd(38)}│`);
  console.log('└─────────────────────────────────────────────────────┘');
  console.log('\n⚠️  Esta contraseña NO volverá a mostrarse.\n');

  await prisma.$disconnect();
}

main().catch((e) => {
  console.error('❌ Error al crear el administrador:', e.message);
  prisma.$disconnect();
  process.exit(1);
});
