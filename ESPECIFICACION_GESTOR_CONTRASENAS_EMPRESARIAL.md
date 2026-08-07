# ESPECIFICACIÓN TÉCNICA PARA DESARROLLAR UNA APLICACIÓN PROFESIONAL DE GESTIÓN DE CONTRASEÑAS EMPRESARIALES

Utiliza este documento como especificación completa. No tomes decisiones
importantes sin consultarme previamente. La prioridad absoluta del
proyecto es la **seguridad**, por encima de la velocidad de desarrollo o
la simplicidad.

## OBJETIVO DEL PROYECTO

Desarrollar una aplicación web profesional de gestión de contraseñas
para uso interno de la empresa.

La aplicación estará alojada en Internet mediante HTTPS y únicamente
podrán acceder usuarios autorizados mediante autenticación segura.

El objetivo es disponer de un repositorio centralizado donde almacenar
todas las credenciales de la empresa de forma cifrada, con control
absoluto sobre quién puede acceder a cada información.

La seguridad debe estar diseñada bajo un enfoque **Zero Trust** y
siguiendo las mejores prácticas de ciberseguridad utilizadas por
gestores de contraseñas profesionales.

## PRIORIDADES DEL PROYECTO

1.  Seguridad
2.  Integridad de la información
3.  Auditoría completa
4.  Facilidad de uso
5.  Rapidez

Nunca sacrificar seguridad por comodidad.

## TECNOLOGÍA

### Frontend

-   React
-   Next.js
-   TypeScript
-   Tailwind CSS

### Backend

-   Node.js
-   API REST

### Base de datos

-   PostgreSQL

### ORM

-   Prisma

### Autenticación

-   JWT de corta duración
-   Refresh Tokens
-   Cookies HttpOnly

### Infraestructura

-   Docker
-   Nginx Reverse Proxy

## CIBERSEGURIDAD (OBLIGATORIO)

-   Cifrado AES-256-GCM para los secretos.
-   Derivación de claves mediante Argon2id.
-   Hash Argon2id para contraseñas de usuarios.
-   HTTPS obligatorio con TLS moderno.
-   HSTS, CSP, X-Frame-Options, X-Content-Type-Options y
    Referrer-Policy.
-   Protección contra SQL Injection, XSS, CSRF, SSRF, Clickjacking,
    Directory Traversal, Command Injection, Brute Force, Credential
    Stuffing, Session Hijacking, Session Fixation, Replay Attack, Timing
    Attack y ataques DoS básicos.
-   MFA compatible con Google Authenticator, Microsoft Authenticator,
    Authy y OTP RFC6238.
-   Gestión segura de sesiones, cierre automático por inactividad y
    revocación inmediata.
-   Registro de dispositivos, alertas de seguridad y auditoría completa.
-   RBAC con permisos granulares.
-   Generador y auditor de contraseñas.
-   Importación y exportación controlada y auditada.
-   Backups cifrados.
-   Dashboard administrativo.
-   Logs inmutables.
-   Arquitectura preparada para WebAuthn, Entra ID, LDAP y SSO.
-   Código documentado, pruebas, Docker, CI/CD y manuales.

## AUDITORÍA

Registrar todas las acciones con: - Usuario - Fecha - Hora - IP -
Ubicación - Dispositivo - Navegador - Sistema operativo - Acción -
Resultado - Nivel de riesgo - ID de sesión - User-Agent

## REQUISITOS CRÍTICOS

-   Toda visualización o copia de una contraseña debe quedar registrada.
-   Reautenticación para operaciones críticas.
-   Gestión de claves mediante un gestor de secretos.
-   Mecanismo Break Glass para emergencias.
-   Arquitectura preparada para producción y auditorías OWASP ASVS.

## FORMA DE TRABAJO

1.  Diseñar la arquitectura.
2.  Diseñar la base de datos.
3.  Diseñar la arquitectura de seguridad.
4.  Definir la estructura del proyecto.
5.  Desarrollar por módulos.
6.  Documentar continuamente.
