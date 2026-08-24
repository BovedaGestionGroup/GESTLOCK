#!/usr/bin/env node
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import { randomBytes } from 'crypto';
import * as readline from 'readline';

const RENDER_PROD_DB_URL = "postgresql://gestor_user:71K2ziq3kPgsgK6x7Uhmdxduy4ZZTXqg@dpg-d9su1r5bedkc73e92r30-a.oregon-postgres.render.com/gestor_db_z0ec";

// Si se define DATABASE_URL por entorno de terminal, se usa; si no, se conecta a Render por defecto.
const targetDbUrl = (process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('127.0.0.1'))
  ? process.env.DATABASE_URL
  : RENDER_PROD_DB_URL;

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: targetDbUrl,
    },
  },
});

function generateStrongPassword() {
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

  console.log(`Conectando a base de datos: ${targetDbUrl.includes('render.com') ? 'Render (Producción)' : 'Local'}\n`);

  let adminEmail = process.env.ADMIN_EMAIL;
  if (!adminEmail) {
    adminEmail = await askQuestion('Email del administrador: ');
  }

  if (!adminEmail || !adminEmail.includes('@')) {
    console.error('❌ Email inválido. Abortando.');
    process.exit(1);
  }

  const normalizedEmail = adminEmail.toLowerCase().trim();

  // Comprobar si ya existe
  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });
  if (existing) {
    console.error(`❌ Ya existe un usuario con el email "${normalizedEmail}". Abortando para no sobreescribir.`);
    await prisma.$disconnect();
    process.exit(1);
  }

  // Generar contraseña segura
  const password = generateStrongPassword();
  const passwordHash = await argon2.hash(password);

  // Crear el usuario admin
  const admin = await prisma.user.create({
    data: {
      email: normalizedEmail,
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
