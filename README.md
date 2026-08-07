# Gestor de Contraseñas Empresarial

## Estado actual

Se ha creado una base funcional del proyecto con:

- Monorepo con dos aplicaciones: API y frontend.
- API Express con endpoint de salud en `/health`.
- Frontend Next.js con Tailwind CSS.
- Docker Compose para PostgreSQL.
- Pruebas iniciales del endpoint de salud.

## Requisitos

- Node.js 20+
- Docker Desktop
- npm

## Ejecución

1. Instalar dependencias:
   ```bash
   npm install
   ```

2. Levantar PostgreSQL:
   ```bash
   docker compose up -d
   ```

3. Iniciar la API:
   ```bash
   npm run dev:api
   ```

4. Iniciar el frontend:
   ```bash
   npm run dev
   ```

## Verificación

Ejecutar:

```bash
npm test
```

Resultado esperado: 1 test pasando.
