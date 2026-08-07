# PLAN DE DESARROLLO POR ETAPAS - GESTOR DE CONTRASEÑAS EMPRESARIAL

## Objetivo

Desarrollar la aplicación de forma incremental. Ninguna etapa comienza
hasta que la anterior esté finalizada, probada y documentada.

## ETAPA 1 - Planificación

-   Definir requisitos funcionales y no funcionales.
-   Diseñar la arquitectura.
-   Seleccionar tecnologías.
-   Definir estándares de código.
-   Crear backlog.

**Entregables:** arquitectura, roadmap y documentación.

## ETAPA 2 - Base del proyecto

-   Crear repositorio.
-   Configurar Next.js, TypeScript y Tailwind.
-   Configurar Node.js, Prisma y PostgreSQL.
-   Docker Compose.
-   Variables de entorno.
-   CI/CD.

**Entregables:** proyecto compilando y entorno reproducible.

## ETAPA 3 - Base de datos

-   Modelo entidad-relación.
-   Migraciones Prisma.
-   Índices, claves y restricciones.
-   Datos iniciales.

## ETAPA 4 - Autenticación

-   Login.
-   Argon2id.
-   JWT + Refresh Tokens.
-   Cookies HttpOnly.
-   MFA TOTP.
-   Recuperación segura.

## ETAPA 5 - Gestión de usuarios y roles

-   CRUD de usuarios.
-   RBAC.
-   Permisos granulares.
-   Gestión de sesiones.

## ETAPA 6 - Bóveda de contraseñas

-   Carpetas y subcarpetas.
-   CRUD de credenciales.
-   Cifrado AES-256-GCM.
-   Adjuntos.
-   Buscador.

## ETAPA 7 - Auditoría

-   Registro de todos los eventos.
-   Historial completo.
-   Filtros y exportación.

## ETAPA 8 - Seguridad avanzada

-   Rate limiting.
-   Protección OWASP Top 10.
-   Cabeceras de seguridad.
-   Reautenticación.
-   Alertas.

## ETAPA 9 - Panel de administración

-   Dashboard.
-   Estadísticas.
-   Gestión de usuarios.
-   Configuración.

## ETAPA 10 - Importación y exportación

-   CSV.
-   Excel.
-   KeePass.
-   Bitwarden.
-   Exportaciones cifradas.

## ETAPA 11 - Backups

-   Copias automáticas.
-   Restauración.
-   Verificación.

## ETAPA 12 - Pruebas

-   Unitarias.
-   Integración.
-   End-to-end.
-   Seguridad.

## ETAPA 13 - Producción

-   Despliegue.
-   Hardening.
-   Monitorización.
-   Manuales.

## Regla obligatoria para el agente

Antes de iniciar cada etapa deberá: 1. Explicar el objetivo. 2. Indicar
los archivos que va a crear o modificar. 3. Esperar confirmación si hay
decisiones funcionales. 4. Implementar. 5. Ejecutar pruebas. 6. Corregir
errores. 7. Actualizar la documentación. 8. No avanzar a la siguiente
etapa hasta recibir aprobación.
