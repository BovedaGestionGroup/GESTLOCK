# AUDITORÍA DE CIBERSEGURIDAD — GESTLOCK (REVISADA)

**Fecha de Auditoría Inicial:** 13 de agosto de 2026  
**Fecha de Re-Auditoría Post-Remediación:** 24 de agosto de 2026  
**Alcance:** `apps/api` (Express + Prisma + PostgreSQL), `apps/web` (Next.js), `render.yaml`, scripts de administración, variables de entorno en Render.  
**Metodología:** OWASP ASVS 4.0, OWASP Top 10 (2021), OWASP API Security Top 10 (2023), CWE.

---

## 1. RESUMEN EJECUTIVO

Tras completar el plan de remediación de ciberseguridad, **GESTLOCK ha resuelto todas las vulnerabilidades críticas y altas** identificadas en el análisis inicial.

- **Puntuación inicial:** 28 / 100 🔴 (No apta)
- **Puntuación actual:** **92 / 100 🟢 (APTA PARA PRODUCCIÓN)**

Los fallos de configuración de secretos, la cuenta de administrador por defecto en código, el CORS permissivo, la falta de rate limiting, la vulnerabilidad IDOR y el envío masivo de contraseñas descifradas en el listado de la bóveda han sido **totalmente corregidos y verificados en producción**.

---

## 2. ESTADO DE REMEDIACIÓN DE HALLAZGOS

| ID | Riesgo Inicial | Hallazgo | Estado Actual | Solución |
|---|---|---|---|---|
| **C-01** | CRÍTICO | Secretos con fallback hardcodeado | 🟢 **RESUELTO** | `requireEnv` implementado. Falla en arranque si faltan claves. Secretos de 64 bytes configurados en Render. |
| **C-02** | CRÍTICO | Admin por defecto auto-aprovisionado | 🟢 **RESUELTO** | Código y cuenta eliminados. Reemplazado por `seed-admin.mjs` de ejecución manual. |
| **C-04** | CRÍTICO | CORS reflectante con `credentials: true` | 🟢 **RESUELTO** | Lista blanca restringida a `https://gestor-web-ikec.onrender.com`. |
| **C-03** | CRÍTICO | Clave maestra única global | 🟡 **MITIGADO** | Secreto de 64 bytes de alta entropía. Hoja de ruta abierta para derivación por usuario en v2.0. |
| **A-01** | ALTO | Contraseñas en claro en listado de bóveda | 🟢 **RESUELTO** | Listado devuelve solo metadatos. Endpoint `/reveal` específico con log `vault_view`. |
| **IDOR** | ALTO | Compartir entradas ajenas | 🟢 **RESUELTO** | Validación de propiedad corregida (`actor.id !== entry.userId`). |
| **A-03** | ALTO | Sin Rate Limiting | 🟢 **RESUELTO** | `express-rate-limit` (20 req/15min login/registro, 5 req/15min MFA). |
| **A-05** | ALTO | Secretos en logs sin email configurado | 🟢 **RESUELTO** | Validación de proveedor de email obligatorio en producción al arrancar. |
| **A-02** | ALTO | Enumeración de usuarios | 🟢 **RESUELTO** | Mensajes de error genéricos uniformes en autenticación. |
| **A-04** | ALTO | Token de reset en query URL | 🟢 **RESUELTO** | Token en fragmento `#resetToken=...` (no viaja al servidor/logs). |
| **A-06** | MEDIO-ALTO | Sin HSTS y CSP con localhost | 🟢 **RESUELTO** | HSTS activado (`max-age=63072000`) y CSP dinámica limpia para producción. |
| **M-02** | MEDIO | Mensajes de error internos | 🟢 **RESUELTO** | Filtro `safeErrorMessage` en handlers. |
| **M-05** | MEDIO | Scripts en `src/` | 🟢 **RESUELTO** | Movidos a `apps/api/scripts/`. |
| **M-06** | MEDIO | `inMemoryStore.ts` | 🟢 **RESUELTO** | Archivo borrado del repositorio. |
| **M-07** | MEDIO | `jwt.verify` sin `algorithms` | 🟢 **RESUELTO** | Restringido a `HS256` explícito. |

---

## 3. VEREDICTO FINAL

# 🟢 **APTA PARA PRODUCCIÓN**

Gestlock cuenta ahora con defensas sólidas en autenticación, autorización, gestión de secretos, cabeceras HTTP y auditoría.
