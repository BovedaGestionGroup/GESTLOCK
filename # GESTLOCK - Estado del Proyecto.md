# GESTLOCK - Estado del Proyecto

## Objetivo

Publicar la aplicación GESTLOCK (Gestor Empresarial de Contraseñas) en Render utilizando:

- GitHub
- Render
- PostgreSQL
- Prisma
- Node.js
- Express
- Next.js
- TypeScript
- npm Workspaces (Monorepo)

---

# Estructura del proyecto

```
GESTOR DE CONTRASEÑAS/
│
├── apps/
│   ├── api/
│   └── web/
│
├── package.json
├── render.yaml
└── ...
```

Monorepo usando npm Workspaces.

package.json raíz:

```json
{
  "private": true,
  "workspaces": [
    "apps/*"
  ]
}
```

---

# Frontend

Ubicación

```
apps/web
```

Framework

- Next.js 14
- React 18

package.json

```json
{
  "scripts": {
    "dev": "next dev -p 3000",
    "build": "next build",
    "start": "next start -p ${PORT:-3000}"
  }
}
```

---

# Backend

Ubicación

```
apps/api
```

Tecnologías

- Express
- TypeScript
- Prisma
- PostgreSQL
- JWT
- Argon2
- Cookie Parser

package.json

```json
{
  "scripts": {
    "dev": "tsx watch src/index.ts",
    "build": "tsc -p tsconfig.json",
    "start": "node dist/index.js"
  }
}
```

---

# Base de datos

Prisma

schema.prisma

Modelos

- User
- RefreshToken
- AuditLog
- VaultEntry
- VaultEntryShare

Datasource

```prisma
datasource db {
  provider = "postgresql"
  url = env("DATABASE_URL")
}
```

---

# GitHub

Repositorio

https://github.com/BovedaGestionGroup/GESTLOCK

Se inicializó Git.

Se hizo:

```
git init
git add .
git commit -m "Primer commit"
git branch -M main
git push -u origin main
```

Hubo un problema porque Git estaba autenticado con otro usuario
(FernandoGestionGroup).

Finalmente quedó autenticado correctamente con:

BovedaGestionGroup

Repositorio subido correctamente.

---

# Render

Se creó un Web Service.

Configuración utilizada

Root Directory

```
apps/api
```

Build Command

```
npm install && npx prisma generate && npx prisma db push && npm run build
```

Start Command

```
npm start
```

Variables

```
DATABASE_URL
JWT_SECRET
NODE_ENV=production
```

---

# PostgreSQL

Render creó correctamente la base de datos.

Prisma ejecutó correctamente:

```
npx prisma generate
```

y

```
npx prisma db push
```

Las tablas fueron creadas correctamente.

La conexión con PostgreSQL funciona.

---

# render.yaml

Existe un render.yaml.

Contenido

```yaml
services:
  - type: web
    name: gestor-web
    env: node

  - type: web
    name: gestor-api
    env: node
```

No se está utilizando actualmente porque el despliegue se está haciendo desde la interfaz de Render.

---

# index.ts

El backend escucha correctamente el puerto de Render.

Actualmente tiene:

```ts
app.listen(process.env.PORT ? Number(process.env.PORT) : 4000)
```

Eso es correcto.

Solo se sugirió cambiar el console.log.

También se detectó que el CSP contiene:

```
connect-src 'self' http://localhost:3000
```

En producción habrá que sustituir localhost por:

```
https://gestlock-web.onrender.com
```

o usar una variable

```
FRONTEND_URL
```

---

# Estado actual

La compilación TypeScript del backend funciona localmente.

Se corrigió la declaración de dependencias: `argon2` y `cookie-parser`
pertenecen ahora a `apps/api`, y el `package-lock.json` está sincronizado.
Esto permite que el backend instale sus dependencias aunque Render use
`apps/api` como Root Directory.

La variable `DATABASE_URL` local ya está configurada con una URL PostgreSQL
válida y coincide con `docker-compose.yml`. Las pruebas quedan pendientes
de ejecutarse cuando haya un servidor PostgreSQL disponible en
`localhost:5432`; actualmente Prisma devuelve el error `P1001` porque no
hay ningún servidor escuchando en ese puerto.

---

# Log de Render

Los primeros pasos funcionan:

✓ npm install

✓ prisma generate

✓ prisma db push

✓ Base de datos sincronizada

El error ocurre en:

```
tsc -p tsconfig.json
```

Errores principales

```
Cannot find name 'process'

Cannot find name 'Buffer'

Cannot find name 'crypto'

Cannot find module 'argon2'

Cannot find module 'express'

Cannot find module 'cookie-parser'

Cannot find module 'cors'

Cannot find module 'jsonwebtoken'

Cannot find module 'vitest'

Cannot find module 'supertest'

Could not find declaration file...
```

Hay decenas de errores derivados del mismo problema.

---

# tsconfig actual

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true
  },
  "include": [
    "src/**/*.ts"
  ]
}
```

Se sospecha que falta:

```json
"types": ["node"]
```

y posiblemente:

```json
"lib": ["ES2022"]
```

pero no parece ser el único problema.

---

# Hipótesis actual

El proyecto utiliza npm Workspaces.

Render está haciendo:

```
npm install
```

desde

```
apps/api
```

Eso provoca que las dependencias del monorepo no queden correctamente resueltas durante la compilación.

Hay que revisar:

- estrategia de instalación de npm workspaces
- ubicación real de node_modules
- tsconfig
- dependencias devDependencies
- package-lock
- posible necesidad de ejecutar npm install desde la raíz

---

# Lo que debe investigar la siguiente IA

1. Revisar si Render está compilando correctamente un monorepo npm workspaces.

2. Verificar si el Build Command debe ejecutarse desde la raíz.

3. Revisar tsconfig.

4. Revisar package-lock.

5. Revisar configuración de TypeScript para NodeNext.

6. Revisar por qué tsc no detecta:

- process
- Buffer
- express
- argon2
- jsonwebtoken
- cookie-parser
- cors

cuando esas dependencias existen.

7. Determinar si Render necesita:

```
npm install --workspaces
```

o

```
npm ci
```

o un Root Directory diferente.

---

# Objetivo final

Conseguir que Render compile correctamente el backend y publicar:

Backend

```
https://gestlock-api.onrender.com
```

Frontend

```
https://gestlock-web.onrender.com
```

utilizando PostgreSQL + Prisma.