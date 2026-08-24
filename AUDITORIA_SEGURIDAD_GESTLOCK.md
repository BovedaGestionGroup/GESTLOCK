# AUDITORÍA DE CIBERSEGURIDAD — GESTLOCK
**Fecha:** 13 de agosto de 2026
**Alcance:** `apps/api` (Express + Prisma + PostgreSQL), `apps/web` (Next.js), `render.yaml`, scripts operativos, esquema de base de datos, documentación de despliegue.
**Metodología:** OWASP ASVS, OWASP Top 10, OWASP API Security Top 10, OWASP Authentication/Session/Cryptographic Storage Cheat Sheets, CWE.

> Esta auditoría es de solo lectura. No se ha modificado ningún archivo. Todos los hallazgos están basados en el código realmente presente en el repositorio, no en suposiciones.

---

## 1. RESUMEN EJECUTIVO

Gestlock tiene una base de código razonablemente ordenada (Argon2id para contraseñas de usuario, AES-256-GCM autenticado para secretos de la bóveda, Zod para validación, JWT de corta duración con refresh tokens revocables en BD). Sin embargo, la auditoría ha encontrado **varios fallos críticos de configuración y arquitectura que, de estar presentes en el despliegue real de Render, permiten la toma de control total de la aplicación y el descifrado masivo de todas las contraseñas almacenadas**, sin necesidad de ninguna vulnerabilidad "sofisticada".

El hallazgo más grave es que **`render.yaml` no define `JWT_SECRET`, `JWT_REFRESH_SECRET` ni `VAULT_MASTER_SECRET`** como variables de entorno del servicio `gestor-api`, mientras que el código tiene *fallbacks* hardcodeados (`dev-secret`, `dev-refresh-secret`, `dev-master-secret`) para esos mismos valores. Si esas variables no se han añadido manualmente desde el panel de Render (algo que no se puede confirmar solo con el código), **la API en producción está firmando JWT y cifrando todas las contraseñas con secretos públicos, conocidos y presentes en el propio repositorio**.

A esto se suma una cuenta de administrador con credenciales por defecto (`info@gestiongroup.es` / `Gestion2026.`) auto-aprovisionada en el primer login, una configuración de CORS que refleja cualquier origen con `credentials: true`, ausencia total de rate limiting/bloqueo de cuentas, y una arquitectura de cifrado de "clave maestra única para todos los usuarios" que contradice el requisito de **Zero Trust** exigido en la especificación del proyecto.

**Veredicto: Gestlock NO debe ponerse en producción en su estado actual.**

---

## 2. ARQUITECTURA DE SEGURIDAD ACTUAL (mapa de reconocimiento)

| Componente | Implementación encontrada |
|---|---|
| Frontend | Next.js (`apps/web/app/page.tsx`), fetch directo a la API, tokens en `localStorage` |
| Backend | Express (`apps/api/src/index.ts`), rutas monolíticas en un único archivo |
| Autenticación | Argon2id (password hash) + JWT de acceso (15 min) + refresh token JWT persistido en BD (`apps/api/src/auth.ts`) |
| Autorización | Jerarquía de roles simple `user < auditor < admin` (`hasPermission`) |
| Sesiones | Access token en `Authorization: Bearer`, refresh token también en cookie `httpOnly` |
| Cifrado de secretos | AES-256-GCM con clave derivada vía `scryptSync(secret, 'gestor-salt', 32)` — **clave única global**, no por usuario |
| 2FA | TOTP vía `otplib`, opcional |
| Recuperación de contraseña | Solo iniciable por un admin (`/admin/users/:id/send-reset-password`), token aleatorio de 32 bytes, expira 1h |
| Base de datos | PostgreSQL vía Prisma, modelos `User`, `RefreshToken`, `AuditLog`, `VaultEntry`, `VaultEntryShare`, `PasswordResetToken` |
| CORS | `cors({ origin: true, credentials: true })` — refleja cualquier origen |
| Rate limiting | **No existe en ningún endpoint** |
| CSRF | No hay token CSRF; mitigación parcial vía `SameSite=lax` en la cookie de refresh |
| Cabeceras de seguridad | Middleware manual: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP básica. **Sin HSTS** |
| Auditoría | `AuditLog` registra login, registro, creación/edición/borrado de bóveda, compartir, cambios de rol — **no registra visualización ni copia de contraseñas** |
| Despliegue | Render (`render.yaml`), `startCommand` ejecuta `prisma db push` antes de arrancar el servidor |
| Scripts operativos | `verify-all-prod.mjs`, `verify-existing-users.mjs`, `delete-user.mjs` sueltos en `src/`, ejecutables directamente contra `DATABASE_URL` |

---

## 3. FORTALEZAS DETECTADAS

Para que el informe sea objetivo, esto está **bien hecho**:

- **Hashing de contraseñas de usuario con Argon2id** (`argon2.hash` / `argon2.verify` en `auth.ts`) — algoritmo correcto y resistente, no hay que "arreglar" esto.
- **Cifrado de secretos con AES-256-GCM auténtico**: IV aleatorio de 12 bytes por operación, `authTag` verificado en el descifrado, formato `iv:cipher:tag`. No hay reutilización de IV ni modo ECB/CBC sin autenticar. La *construcción* criptográfica es correcta; el problema (ver §9) es la **gestión de la clave**, no el algoritmo.
- **Refresh tokens revocables**: no basta con que el JWT sea válido; se comprueba también su existencia y estado (`revoked`, `expiresAt`) en la tabla `RefreshToken`, lo que permite invalidar sesiones reales (logout revoca en BD).
- **Validación con Zod** en registro/login (`registerSchema`, `loginSchema`), incluida comprobación de confirmación de contraseña.
- **Autorización server-side real**: los endpoints de admin (`/admin/*`) comprueban el rol del actor consultando la BD (`hasPermission(actor.role, 'admin')`), no confían en un claim del JWT ni en el frontend.
- **MFA (TOTP) implementado correctamente en el flujo de login**: si `mfaEnabled` es true, el login exige y verifica el código antes de emitir tokens.
- Contraseñas de usuario nunca se registran en `console.log` ni se guardan en claro en la tabla `User`.

---

## 4. VULNERABILIDADES CRÍTICAS

### [C-01] Secretos criptográficos con fallback hardcodeado y ausentes en `render.yaml`

**Severidad:** CRÍTICA — **CVSS estimado: 9.8**
**Categoría:** CWE-798 (Use of Hard-coded Credentials), CWE-321 (Use of Hard-coded Cryptographic Key), OWASP A02:2021 (Cryptographic Failures) / A07:2021 (Identification and Authentication Failures)

**Ubicación:**
- `apps/api/src/auth.ts` → `getJwtSecret()` (`process.env.JWT_SECRET ?? 'dev-secret'`), `getRefreshJwtSecret()` (`'dev-refresh-secret'`)
- `apps/api/src/index.ts` → `deriveEncryptionKey(process.env.VAULT_MASTER_SECRET ?? 'dev-master-secret')`
- `render.yaml` → servicio `gestor-api`, sección `envVars`

**Descripción:**
El código tiene *fallbacks* explícitos a valores fijos si las variables de entorno no están definidas. `render.yaml`, que es el manifiesto de despliegue real del proyecto, **solo define `NODE_ENV` y `DATABASE_URL`** para el servicio `gestor-api`. No aparece `JWT_SECRET`, `JWT_REFRESH_SECRET` ni `VAULT_MASTER_SECRET`.

```yaml
- type: web
  name: gestor-api
  ...
  envVars:
    - key: NODE_ENV
      value: production
    - key: DATABASE_URL
      fromDatabase:
        name: gestor-db
        property: connectionString
```

**Por qué es vulnerable:**
Si esas tres variables no se han configurado manualmente en el panel de Render (algo que no se puede verificar desde el código, y que la propia forma en que están redactados los *fallbacks* sugiere que en algún momento no lo estuvieron), la API en producción:
1. Firma y verifica **todos los JWT de acceso y refresco con el secreto público `dev-secret` / `dev-refresh-secret`**, ambos visibles en el repositorio.
2. Deriva **la clave de cifrado de TODAS las contraseñas de la bóveda de TODOS los usuarios** a partir de la cadena literal `dev-master-secret` con la sal fija `gestor-salt` (también hardcodeada, ver C-03).

**Escenario de ataque:**
Un atacante externo, sin necesidad de comprometer la base de datos ni el servidor:
1. Lee el repositorio (público o con acceso de lectura) y obtiene los tres valores por defecto.
2. Firma un JWT propio: `jwt.sign({ sub: '<id_de_admin>' }, 'dev-secret')` y lo usa como `Authorization: Bearer` contra cualquier endpoint protegido, incluidos los de administrador — **sin necesidad de contraseña, MFA ni cuenta real**.
3. Si además obtiene una copia de la base de datos (por cualquier otro vector, incluso un simple *dump* filtrado), deriva `scryptSync('dev-master-secret', 'gestor-salt', 32)` y descifra el campo `password` de cada `VaultEntry` sin más esfuerzo.

**Impacto:** Bypass total de autenticación (suplantación de cualquier usuario, incluido admin) + descifrado masivo de todas las credenciales almacenadas por la empresa. Compromiso completo de la aplicación.

**Corrección recomendada:**
- Eliminar **todos** los *fallbacks* hardcodeados de secretos (`dev-secret`, `dev-refresh-secret`, `dev-master-secret`, `dev-user`/`dev-password` de la URL de BD por defecto). Si la variable no existe, la aplicación debe **fallar al arrancar** (`throw` en el bootstrap), nunca degradar silenciosamente a un valor conocido.
- Añadir explícitamente `JWT_SECRET`, `JWT_REFRESH_SECRET` y `VAULT_MASTER_SECRET` a `render.yaml` como `sync: false` (para que Render obligue a introducirlos manualmente y no los versione) o gestionarlos vía Render "Secret Files"/"Environment Groups".
- Rotar inmediatamente estos tres secretos en producción, lo que invalidará todas las sesiones activas y **hará irrecuperables con la clave antigua todas las contraseñas ya cifradas** — es necesario un proceso de re-cifrado (descifrar con la clave vieja, volver a cifrar con la nueva) antes de rotar, no después.

**Prioridad:** INMEDIATA (bloqueante para producción)

---

### [C-02] Cuenta de administrador con credenciales por defecto auto-aprovisionadas

**Severidad:** CRÍTICA — **CVSS estimado: 9.1**
**Categoría:** CWE-798, CWE-16 (Configuration), OWASP A07:2021

**Ubicación:** `apps/api/src/auth.ts` → `getDefaultAdminCredentials()`, usado dentro de `authenticateUser()`; `apps/api/.env.example`

**Descripción:**
```ts
function getDefaultAdminCredentials() {
  return {
    email: process.env.DEFAULT_ADMIN_EMAIL ?? 'info@gestiongroup.es',
    password: process.env.DEFAULT_ADMIN_PASSWORD ?? 'Gestion2026.',
  };
}
```
Si alguien intenta iniciar sesión con `info@gestiongroup.es` / `Gestion2026.` y ese usuario **todavía no existe** en la base de datos, `authenticateUser` lo **crea automáticamente con rol `admin`** y lo autentica en el acto. Estas mismas credenciales están además impresas en `.env.example`, en el archivo de tests (`index.test.ts`) y en el `README`/documentación de estado del proyecto (todas coincidentes), lo que confirma que es un valor real y reutilizado, no solo un placeholder.

**Por qué es vulnerable:** Es un backdoor de administrador con contraseña conocida y publicada, que además se auto-crea la primera vez que alguien la usa (no requiere que ya exista la cuenta).

**Escenario de ataque:** Un atacante que conoce (por el repositorio, público o filtrado) el patrón `info@gestiongroup.es` / `Gestion2026.` inicia sesión directamente contra `https://gestor-api-vjy0.onrender.com/auth/login`. Si nadie ha creado antes esa cuenta con otra contraseña, obtiene una cuenta admin nueva y válida al instante.

**Impacto:** Compromiso de cuenta administradora completa: gestión de usuarios, visualización de todas las credenciales compartidas, cambio de roles, borrado de usuarios.

**Corrección recomendada:** Eliminar por completo el auto-aprovisionamiento de un admin con contraseña fija en tiempo de ejecución. La cuenta inicial de administrador debe crearse mediante un script de *seed* ejecutado una única vez de forma manual y segura (contraseña generada aleatoriamente y comunicada por canal seguro), nunca como *fallback* accesible desde el endpoint público de login.

**Prioridad:** INMEDIATA

---

### [C-03] Arquitectura de cifrado con clave maestra única global (viola el requisito de Zero Trust)

**Severidad:** CRÍTICA — **CVSS estimado: 8.6**
**Categoría:** CWE-320 (Key Management Errors), OWASP A02:2021

**Ubicación:** `apps/api/src/auth.ts` → `deriveEncryptionKey()`; usada en todos los `vault/entries*` de `index.ts`

**Descripción:** Todas las contraseñas de la bóveda, de todos los usuarios y empresas, se cifran/descifran con **una única clave global** derivada de `VAULT_MASTER_SECRET` con una **sal estática y compartida** (`'gestor-salt'`, igual para todos los secretos, no por usuario ni por entrada).

**Por qué es vulnerable:** El propio backend puede leer en claro el 100% de las contraseñas de todos los usuarios en cualquier momento (lo hace en cada `GET /vault/entries`, ver A-01). No existe separación criptográfica entre usuarios: comprometer `VAULT_MASTER_SECRET` una sola vez descifra absolutamente todo. Esto es lo opuesto a un diseño *Zero Trust* / *zero-knowledge*, que es un requisito explícito de `ESPECIFICACION_GESTOR_CONTRASENAS_EMPRESARIAL.md`. Además, la especificación exige **Argon2id** para derivación de claves; el código usa `scryptSync` con parámetros por defecto de Node (coste bajo respecto a recomendaciones actuales de OWASP para scrypt).

**Escenario de ataque:** Cualquier actor que obtenga `VAULT_MASTER_SECRET` (por C-01, por una variable de entorno filtrada, por un empleado con acceso al panel de Render) descifra instantáneamente la bóveda completa de la empresa, no solo la de una cuenta.

**Impacto:** Ausencia de "blast radius" limitado: un único secreto de servidor compromete todos los secretos de todos los clientes/usuarios de la aplicación.

**Corrección recomendada:** Rediseñar el cifrado hacia un esquema por usuario: derivar una clave de cifrado específica por usuario (p. ej. a partir de un secreto del servidor + un salt único por usuario almacenado en BD, o idealmente derivada de material que solo el usuario controla, si se quiere alcanzar *zero-knowledge* real). Sustituir `scryptSync` con parámetros por defecto por Argon2id con parámetros de memoria/iteraciones explícitos y documentados, tal como exige la propia especificación del proyecto.

**Prioridad:** ALTA (rediseño, no bloqueante inmediato si C-01 se corrige primero, pero debe planificarse antes de escalar el número de usuarios)

---

### [C-04] CORS que refleja cualquier origen con `credentials: true`

**Severidad:** CRÍTICA — **CVSS estimado: 8.1**
**Categoría:** CWE-942 (Overly Permissive CORS), OWASP A05:2021 (Security Misconfiguration)

**Ubicación:** `apps/api/src/index.ts` → `app.use(cors({ origin: true, credentials: true }));`

**Descripción:** `origin: true` en el middleware `cors` hace que Express **refleje dinámicamente el `Origin` de cada petición** en `Access-Control-Allow-Origin`, combinado con `Access-Control-Allow-Credentials: true`. Esto equivale, en la práctica, a permitir **cualquier sitio web** a hacer peticiones autenticadas (con cookies) a la API y leer la respuesta desde JavaScript.

**Por qué es vulnerable:** El login coloca el `refreshToken` en una cookie `httpOnly` con `sameSite: 'lax'`. `SameSite=Lax` bloquea el envío automático de la cookie en peticiones cross-site que no sean de navegación de nivel superior (protege bastante contra CSRF clásico vía `<form>`), **pero no bloquea** peticiones `fetch`/XHR con `credentials: 'include'` lanzadas desde una página maliciosa cuando además el servidor **acepta y refleja** cualquier origen. En este escenario, una web controlada por el atacante puede:
```js
fetch('https://gestor-api-vjy0.onrender.com/auth/refresh', { method: 'POST', credentials: 'include' })
  .then(r => r.json()).then(data => exfiltrate(data.accessToken, data.refreshToken));
```
y el navegador de la víctima adjunta la cookie porque el `Origin` del atacante es reflejado como permitido con `credentials: true`.

**Escenario de ataque:** Víctima autenticada en Gestlock visita una página controlada por el atacante (o un anuncio/iframe malicioso) mientras su cookie de refresh sigue vigente (hasta 7 días). El script del atacante llama a `/auth/refresh`, recibe un `accessToken`/`refreshToken` nuevos y válidos, y los exfiltra. A partir de ahí, el atacante tiene una sesión completa de la víctima.

**Impacto:** Secuestro de sesión sin necesidad de robar directamente ninguna cookie ni token; basta con que la víctima cargue una página del atacante.

**Corrección recomendada:** Sustituir `origin: true` por una lista blanca explícita de orígenes de confianza (el dominio real del frontend en Render/producción, y `localhost` solo en desarrollo, condicionado por `NODE_ENV`). Nunca combinar reflejo de origen arbitrario con `credentials: true`.

**Prioridad:** INMEDIATA

---

## 5. VULNERABILIDADES ALTAS

### [A-01] El backend descifra y envía todas las contraseñas al frontend en cada carga de la bóveda, sin registro de auditoría de "visualización"

**Severidad:** ALTA — **CVSS estimado: 7.5**
**Categoría:** OWASP A01:2021 (Broken Access Control) / requisito explícito incumplido del documento de especificación ("Toda visualización o copia de una contraseña debe quedar registrada")

**Ubicación:** `apps/api/src/index.ts` → `GET /vault/entries`; `apps/web/app/page.tsx` → `entries` state, `visiblePasswords`

**Descripción:** El endpoint `GET /vault/entries` descifra **todas** las contraseñas de las entradas visibles para el usuario y las envía en la respuesta JSON, aunque el usuario nunca pulse "Mostrar". En el frontend, `entry.password` en claro se guarda directamente en el `state` de React para cada entrada de la lista; el botón "👁 Mostrar/Ocultar" (`visiblePasswords`) solo cambia si se *renderiza* el texto en pantalla, no si se *solicita* al backend. Esto significa que las contraseñas viajan por red y quedan en memoria del navegador (inspeccionables vía React DevTools o `window` en cualquier momento) por el simple hecho de tener la pestaña de "Bóveda" abierta, sin que quede ningún registro de auditoría de ese acceso.

**Por qué es vulnerable:** Contradice directamente el requisito crítico "Toda visualización o copia de una contraseña debe quedar registrada" del documento de especificación del proyecto. El `AuditLog` actual solo registra `vault_create`, `vault_update`, `vault_delete`, `vault_share` — nunca `vault_view` ni `vault_copy`. Un administrador (o cualquier atacante con una sesión admin, ver C-02/C-04) puede ver/copiar cualquier contraseña compartida sin dejar rastro.

**Impacto:** Imposibilidad de investigar quién accedió a qué contraseña y cuándo; ampliación de la superficie de exposición de secretos en el cliente.

**Corrección recomendada:** Separar el listado (metadatos: nombre, URL, usuario, fecha) del descifrado de la contraseña, que debería requerir una llamada explícita `GET /vault/entries/:id/reveal` que (a) genere un registro `vault_view` en `AuditLog` y (b) opcionalmente exija reautenticación para operaciones críticas, tal como exige la especificación.

**Prioridad:** ALTA

---

### [A-02] Enumeración de usuarios en registro y verificación de email

**Severidad:** ALTA — **CVSS estimado: 6.5**
**Categoría:** CWE-203 (Observable Discrepancy), OWASP A07:2021

**Ubicación:** `apps/api/src/auth.ts` → `registerUser()` (`throw new Error('User already exists')`); `apps/api/src/index.ts` → `/auth/verify-email` (`'User not found'`, `'Email is already verified'`)

**Descripción:** Estos mensajes de error se devuelven literalmente al cliente (`error.message`), permitiendo a un atacante determinar si un email ya está registrado en Gestlock probando `/auth/register` o `/auth/verify-email` con distintos correos.

**Impacto:** Permite construir listas de empleados/cuentas válidas de la empresa como paso previo a *password spraying* o *phishing* dirigido.

**Corrección recomendada:** Responder siempre con un mensaje genérico ("Si los datos son correctos, recibirás instrucciones por correo") independientemente de si la cuenta existe, tanto en registro como en verificación y en el futuro flujo de recuperación de contraseña self-service.

**Prioridad:** ALTA

---

### [A-03] Ausencia total de rate limiting / bloqueo de cuentas

**Severidad:** ALTA — **CVSS estimado: 7.3**
**Categoría:** CWE-307 (Improper Restriction of Excessive Authentication Attempts), OWASP API4:2023

**Ubicación:** Todo `apps/api/src/index.ts` — ningún middleware de limitación de tasa en `/auth/login`, `/auth/register`, `/auth/mfa/verify`, `/auth/verify-email`, `/auth/reset-password`.

**Descripción:** No hay ningún mecanismo (`express-rate-limit` u otro) que limite intentos repetidos. `/auth/login` y `/auth/mfa/verify` son especialmente sensibles: un atacante puede probar contraseñas o códigos TOTP de 6 dígitos (1,000,000 combinaciones) sin ninguna fricción.

**Impacto:** Fuerza bruta de contraseñas, *credential stuffing*, y — de forma más grave — fuerza bruta del código TOTP de 6 dígitos, que sin límite de intentos es completamente viable en minutos/horas.

**Corrección recomendada:** Rate limiting por IP y por cuenta en todos los endpoints de autenticación; bloqueo temporal progresivo tras N intentos fallidos; en particular, limitar `/auth/mfa/verify` a muy pocos intentos por ventana de tiempo (p. ej. 5 intentos / 15 min).

**Prioridad:** INMEDIATA (bloqueante)

---

### [A-04] Token de restablecimiento de contraseña viaja en la URL (query string)

**Severidad:** ALTA — **CVSS estimado: 6.1**
**Categoría:** CWE-598 (Use of GET Request Method With Sensitive Query Strings)

**Ubicación:** `apps/api/src/index.ts` → `/admin/users/:id/send-reset-password` construye `resetUrl = ${appUrl}?resetToken=${token}&email=...`; `apps/web/app/page.tsx` lee `resetToken`/`email` de `window.location.search`

**Descripción:** El token de un solo uso de restablecimiento de contraseña se transmite como parámetro de consulta en un enlace de email.

**Impacto:** Los tokens en URLs quedan expuestos en historial del navegador, logs de proxies/CDN/Render, y se filtran vía la cabecera `Referer` si la página de reseteo carga cualquier recurso de terceros. Aunque el token expira en 1h y se marca `used`, la ventana de exposición sigue siendo real.

**Corrección recomendada:** Usar un fragmento de URL (`#token=...`, que no se envía al servidor ni aparece en `Referer`) o un formulario POST inicial que intercambie el token por una cookie de un solo uso antes de mostrar el formulario de nueva contraseña.

**Prioridad:** MEDIA-ALTA

---

### [A-05] Posible filtración de secretos en logs cuando el correo no está configurado

**Severidad:** ALTA (condicional) — **CVSS estimado: 6.8**
**Categoría:** CWE-532 (Insertion of Sensitive Information into Log File)

**Ubicación:** `apps/api/src/email.ts` → `sendVerificationEmail`/`sendPasswordResetEmail`, rama `if (!resend) { console.log(...code/url...) }`

**Descripción:** Si `RESEND_API_KEY` (y el fallback `SMTP_USER==='resend'`+`SMTP_PASS`) no están configurados en producción, el código de verificación y la URL de reseteo (con el token, ver A-04) se escriben directamente en la salida estándar del proceso, que en Render queda persistida como logs de aplicación.

**Impacto:** Cualquiera con acceso a los logs de Render (que puede ser un conjunto de personas más amplio que quienes deberían poder ver secretos de usuarios) puede leer códigos de verificación y tokens de reseteo válidos.

**Corrección recomendada:** Que el arranque de la aplicación falle explícitamente en producción si no hay proveedor de email configurado, en lugar de degradar a `console.log` de secretos. Redactar cualquier dato sensible que pudiera llegar a logs.

**Prioridad:** ALTA

---

### [A-06] Ausencia de HSTS y política CSP con referencia a `localhost` hardcodeada en producción

**Severidad:** MEDIA-ALTA — **CVSS estimado: 5.4**
**Categoría:** CWE-319 (parcial), OWASP A05:2021

**Ubicación:** `apps/api/src/index.ts`, middleware de cabeceras: `Content-Security-Policy: ... connect-src 'self' http://localhost:3000`

**Descripción:** No se envía `Strict-Transport-Security`. Además la CSP incluye `http://localhost:3000` como origen permitido de `connect-src` incondicionalmente (no solo en desarrollo), lo cual no aporta seguridad en producción y evidencia que la configuración de CSP no distingue entornos (el propio `# GESTLOCK - Estado del Proyecto.md` señala este mismo punto como pendiente).

**Corrección recomendada:** Añadir `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` (solo detrás de HTTPS, que Render ya provee) y construir la CSP dinámicamente según `NODE_ENV`, apuntando `connect-src` al dominio real del frontend en producción (o a una variable `FRONTEND_URL` como ya se contempla en la documentación del proyecto).

**Prioridad:** MEDIA

---

## 6. VULNERABILIDADES MEDIAS

### [M-01] Derivación de clave `scryptSync` con parámetros por defecto (no Argon2id como exige la especificación)
**Ubicación:** `auth.ts` → `deriveEncryptionKey`. Coste computacional por defecto de Node para `scrypt` es más bajo que las recomendaciones actuales de OWASP; además reutiliza la misma sal para todo (ver C-03). **Corrección:** migrar a Argon2id (ya es dependencia del proyecto) con parámetros explícitos de memoria/tiempo, y sal única por clave derivada.

### [M-02] Mensajes de error con detalle interno expuestos al cliente
**Ubicación:** patrón repetido `res.status(xxx).json({ message: error instanceof Error ? error.message : ... })` en prácticamente todos los handlers de `index.ts`. Puede filtrar mensajes de Prisma/Zod con nombres de columnas o restricciones internas. **Corrección:** capa de mapeo de errores que solo exponga mensajes "seguros" predefinidos; loguear el detalle real solo en servidor.

### [M-03] Falta de comprobación de longitud/complejidad real de contraseña más allá del mínimo de 12 caracteres
**Ubicación:** `registerSchema`/`loginSchema` (`z.string().min(12)`). No hay verificación contra listas de contraseñas comunes/filtradas (p. ej. HaveIBeenPwned range API), pese a que la especificación pide "auditor de contraseñas". **Corrección:** integrar verificación contra breach-lists y feedback de fortaleza en el registro.

### [M-04] `MFA setup` no exige reautenticación
**Ubicación:** `/auth/mfa/setup` solo exige un access token válido de 15 min. Si un atacante roba momentáneamente un access token válido (p. ej. por XSS, ver F-01), podría intentar registrar su propio secreto MFA... aunque `/auth/mfa/verify` sí exige conocer el secreto generado en el mismo flujo, limitando el impacto real. **Corrección:** exigir reintroducción de contraseña antes de habilitar/deshabilitar MFA, tal como pide la especificación para "operaciones críticas".

### [M-05] Scripts operativos de un solo uso conviven en el árbol fuente de la API
**Ubicación:** `apps/api/src/verify-all-prod.mjs`, `verify-existing-users.mjs` (verifican **todos** los usuarios de golpe, saltándose la verificación de email), `delete-user.mjs` (borra un usuario hardcodeado). Se ejecutan con solo tener `DATABASE_URL`. **Corrección:** sacarlos del árbol de despliegue (carpeta `scripts/` fuera de `src`, excluida del build) y protegerlos con confirmación explícita/flags, nunca dejarlos como comandos de un clic contra producción.

### [M-06] Módulo `inMemoryStore.ts` (código muerto) almacena contraseñas de bóveda en texto plano
**Ubicación:** `apps/api/src/lib/inMemoryStore.ts`. Ya no se usa (`index.ts` importa `./lib/prisma.js`), pero si alguien lo reconecta por error, reintroduce almacenamiento de contraseñas sin cifrar. **Corrección:** eliminar el archivo del repositorio.

### [M-07] `jwt.verify` no restringe explícitamente el algoritmo permitido
**Ubicación:** `auth.ts`, `authMiddleware.ts`. No se pasa `{ algorithms: ['HS256'] }`. La librería `jsonwebtoken` v9 mitiga por defecto el ataque clásico "alg: none", pero es una buena práctica de defensa en profundidad no aplicada. **Corrección:** especificar explícitamente el algoritmo esperado en cada `jwt.verify`.

---

## 7. VULNERABILIDADES BAJAS / INFORMACIONALES

- **[B-01]** `X-XSS-Protection: 0` está bien (es lo recomendado hoy, la cabecera está obsoleta y puede introducir problemas), pero conviene documentar por qué para que no se "corrija" por error en el futuro. — INFO.
- **[B-02]** CSP usa `'unsafe-inline'` en `style-src`; riesgo bajo dado que Tailwind/Next a veces lo requieren, pero se recomienda evaluar *nonces* si se refuerza la CSP. — BAJA.
- **[B-03]** `apps/web/public/desktop.ini` versionado (artefacto de Windows Explorer), sin impacto de seguridad pero indica higiene de repositorio mejorable. — INFO.
- **[B-04]** El README y el documento de estado del proyecto contienen la contraseña de administrador por defecto en texto plano como parte de instrucciones — refuerza C-02, tratar como el mismo hallazgo a efectos de remediación.

---

## 8. ESCENARIOS DE COMPROMISO (Fase 16)

**A. Atacante obtiene solo la base de datos.**
Obtiene: hashes Argon2id de contraseñas (no reversibles directamente, requiere fuerza bruta offline costosa — correcto), y **todos los campos `VaultEntry.password` cifrados con AES-256-GCM**. Sin `VAULT_MASTER_SECRET` no puede descifrarlos directamente. *Pero* si C-01 aplica (secreto por defecto en producción), el atacante ya conoce esa clave sin necesidad de nada más → descifra todo.

**B. Atacante obtiene BD + variables de entorno.**
Con `VAULT_MASTER_SECRET` real, descifra el 100% de las contraseñas de la bóveda de todos los usuarios (clave única global, C-03). Con `JWT_SECRET`/`JWT_REFRESH_SECRET` puede forjar sesiones de cualquier usuario indefinidamente.

**C. Atacante compromete una cuenta de usuario normal.**
Puede ver/crear/editar sus propias entradas y las compartidas explícitamente con él (`VaultEntryShare`). No puede ver entradas de otros usuarios no compartidas (el filtro `where.userId` + `shares.some` en `lib/prisma.ts` está correctamente aplicado). Puede intentar `/vault/entries/:id/shares` sobre entradas ajenas, pero el handler exige ser admin o ser el propio dueño (`actor.id !== userId` se compara mal — ver nota técnica abajo) — riesgo MEDIO de revisar más a fondo.

> **Nota técnica adicional detectada durante el análisis de C:** en `POST /vault/entries/:id/shares`, la comprobación es `!actor || (!hasPermission(actor.role,'admin') && actor.id !== userId)`, donde `userId` es el ID del **actor autenticado**, no el propietario de la entrada (`entry.userId`). Es decir, la condición `actor.id !== userId` es **siempre falsa** para cualquier usuario autenticado (comparándose consigo mismo), por lo que en la práctica **cualquier usuario autenticado, no solo el propietario, puede compartir cualquier `VaultEntry` existente con cualquier otro usuario**, sin comprobar que sea el dueño de esa entrada. Esto es un **IDOR (CWE-639)** adicional que degrada el modelo de permisos de "compartir". **Severidad: ALTA.** Corrección: comparar `actor.id !== entry.userId` tras cargar la entrada, antes de decidir autorización.

**D. Atacante compromete una cuenta admin (o crea la de C-02).**
Ve y comparte **todas** las entradas de la bóveda de la empresa (`includeAll: actor?.role === 'admin'`), gestiona usuarios, cambia roles, elimina usuarios, envía enlaces de reseteo de contraseña a cualquier cuenta. Control casi total sin pasar por BD directamente.

**E. Atacante ejecuta JavaScript en el navegador (XSS).**
Los `accessToken`/`refreshToken` se guardan en `localStorage` (`apps/web/app/page.tsx`, `getAuthHeaders`), accesibles desde cualquier script que se ejecute en el origen de la SPA. Un XSS exitoso (no se han encontrado *sinks* obvios de XSS en el código React mostrado, que usa JSX estándar sin `dangerouslySetInnerHTML`, mitigando el riesgo directo) robaría tokens y, además, dado que la vista de bóveda mantiene las contraseñas descifradas en el estado de React (A-01), un XSS también podría leer directamente las contraseñas visibles en memoria.

**F. Atacante con acceso de solo lectura a PostgreSQL.**
Igual que el escenario A: contraseñas de usuario protegidas por Argon2id (correcto); secretos de bóveda protegidos por AES-256-GCM **solo si `VAULT_MASTER_SECRET` es un valor real, robusto y no expuesto** (condicionado a C-01/C-03).

**G. Atacante roba un JWT de acceso.**
Válido 15 minutos, sin revocación posible durante ese margen (es *stateless*). Ventana de exposición limitada, diseño razonable en sí mismo. **Pero** si roba/renueva vía la vulnerabilidad de C-04, puede regenerar tokens indefinidamente (obtiene también un refresh token de 7 días).

**H. Atacante roba la cookie de sesión (`refreshToken`).**
`httpOnly` correcto (no accesible por JS), pero **no `Secure`** salvo en `NODE_ENV==='production'` (`res.cookie(..., { secure: process.env.NODE_ENV === 'production' })`) — depende de que `NODE_ENV` esté bien fijado en Render, lo cual sí se hace en `render.yaml`. Con `sameSite:'lax'`, el mayor riesgo real es la combinación con C-04, no el robo directo de la cookie.

**I. Empleado malicioso con acceso legítimo (admin o usuario con muchas entradas compartidas).**
No existe registro de "quién vio o copió qué contraseña" (A-01), ni reautenticación para operaciones críticas, ni mecanismo *Break Glass* documentado en código (solo mencionado en la especificación, no implementado). Un admin malicioso puede exfiltrar toda la bóveda sin dejar rastro distinguible de un uso legítimo.

---

## 9. CADENAS DE ATAQUE (Fase 17)

**Cadena 1 — De lectura del repositorio a bóveda completa:**
Repositorio público/filtrado (secretos por defecto, C-01) → forjar JWT admin sin contraseña → `GET /vault/entries` como admin (`includeAll: true`) → **bóveda completa de la empresa en texto plano**, sin haber tocado nunca la base de datos.

**Cadena 2 — De una web maliciosa a secuestro de sesión:**
Víctima autenticada visita sitio del atacante → CORS reflectante + `credentials:true` (C-04) → `fetch('/auth/refresh', {credentials:'include'})` exfiltra tokens nuevos → atacante autenticado como la víctima → si la víctima es admin, cadena 1 (bóveda completa); si es usuario normal, acceso a sus entradas + posible abuso del IDOR de "compartir" (Escenario C) para auto-compartirse entradas ajenas si conoce/adivina sus IDs.

**Cadena 3 — Credenciales por defecto a control administrativo:**
`info@gestiongroup.es`/`Gestion2026.` (C-02, publicadas en el propio repo) → login exitoso, cuenta admin auto-creada → gestión total de usuarios y bóveda compartida.

---

## 10. THREAT MODEL (Fase 18)

**Activos:** contraseñas de usuarios (hash), contraseñas de bóveda (cifradas), `VAULT_MASTER_SECRET`, `JWT_SECRET`/`JWT_REFRESH_SECRET`, tokens de sesión, base de datos PostgreSQL, cuentas de administrador.

**Actores:** usuario externo no autenticado; usuario autenticado normal; usuario auditor; administrador; administrador comprometido/malicioso; atacante con acceso de lectura a GitHub/Render; atacante con acceso a la base de datos.

**Superficies de ataque:** frontend público (Next.js en Render), API pública (`gestor-api-vjy0.onrender.com`), repositorio de código (contiene secretos por defecto y credenciales de ejemplo idénticas a las reales), panel de Render (variables de entorno), scripts operativos sueltos en `src/`.

---

## 11. MATRIZ DE RIESGO

| ID | Vulnerabilidad | Severidad | Impacto | Probabilidad | Prioridad |
|---|---|---|---|---|---|
| C-01 | Secretos JWT/cifrado con fallback hardcodeado, ausentes en render.yaml | CRÍTICA | Total | Alta (config no verificable) | INMEDIATA |
| C-02 | Admin con credenciales por defecto auto-aprovisionado | CRÍTICA | Total | Alta | INMEDIATA |
| C-04 | CORS reflectante + credentials:true | CRÍTICA | Alto (secuestro de sesión) | Media-Alta | INMEDIATA |
| C-03 | Clave de cifrado maestra única global (no Zero Trust) | CRÍTICA | Total (blast radius) | Media | ALTA |
| A-01 | Bóveda descifrada completa enviada al cliente sin auditoría de vista | ALTA | Alto | Alta | ALTA |
| Escenario C (nota) | IDOR en compartir entradas de bóveda (`actor.id !== userId`) | ALTA | Alto | Media | ALTA |
| A-03 | Sin rate limiting / bloqueo de cuentas | ALTA | Alto | Alta | INMEDIATA |
| A-05 | Secretos en logs si email no configurado | ALTA | Alto | Media (condicional) | ALTA |
| A-02 | Enumeración de usuarios | ALTA | Medio | Alta | ALTA |
| A-04 | Token de reset en query string | MEDIA-ALTA | Medio | Media | MEDIA-ALTA |
| A-06 | Sin HSTS / CSP con localhost en prod | MEDIA-ALTA | Medio | Alta | MEDIA |
| M-01 | scrypt en vez de Argon2id para derivar clave de cifrado | MEDIA | Medio | Baja-Media | MEDIA |
| M-02 | Mensajes de error verbosos | MEDIA | Bajo-Medio | Alta | MEDIA |
| M-03 | Sin verificación de contraseñas filtradas | MEDIA | Bajo | Media | BAJA-MEDIA |
| M-04 | MFA setup sin reautenticación | MEDIA | Bajo-Medio | Baja | MEDIA |
| M-05 | Scripts operativos peligrosos en `src/` | MEDIA | Medio (operacional) | Baja | MEDIA |
| M-06 | Código muerto con contraseñas en claro | MEDIA | Bajo (si no se reactiva) | Baja | BAJA |
| M-07 | `jwt.verify` sin `algorithms` explícito | MEDIA | Bajo | Baja | BAJA |
| B-01…B-04 | Varios (ver §7) | BAJA/INFO | Bajo | — | BAJA |

---

## 12. PUNTUACIÓN GLOBAL DE SEGURIDAD

**Puntuación: 28 / 100 — No apta para producción.**

Justificación: aunque los primitivos criptográficos elegidos (Argon2id, AES-256-GCM) son correctos y el modelo de datos de autorización server-side está mayormente bien implementado, la combinación de (a) secretos críticos con *fallback* público y ausentes del manifiesto de despliegue, (b) una cuenta de administrador con credenciales conocidas auto-aprovisionada, (c) CORS abierto con credenciales, y (d) ausencia total de rate limiting, constituyen fallos que —de forma individual, cada uno— ya permiten un compromiso total o casi total de la aplicación sin necesidad de técnicas sofisticadas. Para una aplicación cuyo único propósito es custodiar contraseñas empresariales, esto sitúa la puntuación en el tramo más bajo de la escala, independientemente de la calidad del resto del código.

---

## 13. ¿ESTÁ PREPARADA PARA PRODUCCIÓN?

# **NO**

No debe desplegarse (ni seguir operando, si ya está desplegada) hasta que, como mínimo, se resuelvan **C-01, C-02, C-03, C-04, A-01 (mínimo el registro de auditoría), A-03 y el IDOR de "compartir" descrito en el Escenario C**. Dado que no se puede confirmar desde el código si `render.yaml` refleja fielmente la configuración real del servicio en Render, el primer paso **urgente e inmediato**, incluso antes de tocar código, es **verificar manualmente en el panel de Render si `JWT_SECRET`, `JWT_REFRESH_SECRET`, `VAULT_MASTER_SECRET`, `DEFAULT_ADMIN_EMAIL` y `DEFAULT_ADMIN_PASSWORD` están configurados con valores distintos a los que aparecen en el repositorio**. Si no lo están, se debe considerar que la aplicación ya ha estado expuesta con secretos públicamente conocidos y actuar como ante un incidente de seguridad activo (rotación de secretos, revisión de audit logs, notificación si procede).

---

## 14. PLAN DE REMEDIACIÓN

### FASE 1 — BLOQUEANTES (antes de cualquier despliegue o de seguir operando el actual)
1. Verificar en Render si los secretos críticos están realmente configurados; si no, tratarlo como incidente activo.
2. Eliminar todos los *fallbacks* hardcodeados de secretos (C-01); la app debe fallar al arrancar sin ellos.
3. Eliminar el auto-aprovisionamiento del admin por defecto (C-02).
4. Restringir CORS a una lista blanca de orígenes (C-04).
5. Corregir el IDOR de "compartir bóveda" (`actor.id !== entry.userId`).
6. Añadir rate limiting a `/auth/login`, `/auth/register`, `/auth/mfa/verify`, `/auth/reset-password`.

### FASE 2 — SEGURIDAD CRÍTICA (inmediatamente después)
1. Registrar auditoría de `vault_view` / `vault_copy` (A-01) y endpoint diferenciado para revelar contraseña.
2. Sacar los scripts `verify-*-prod.mjs` / `delete-user.mjs` del árbol desplegable y protegerlos.
3. Corregir exposición de secretos en logs cuando el email no está configurado (A-05).
4. Mover el token de reset fuera de la query string (A-04).
5. Genericizar mensajes de error para evitar enumeración de usuarios (A-02) y fuga de detalle interno (M-02).

### FASE 3 — HARDENING
1. Rediseñar el cifrado hacia clave por usuario + Argon2id para derivación (C-03/M-01).
2. Añadir HSTS y CSP consciente del entorno (A-06).
3. Reautenticación obligatoria para habilitar/deshabilitar MFA y otras operaciones críticas (M-04).
4. Verificación de contraseñas filtradas en registro/cambio de contraseña (M-03).
5. Eliminar código muerto (`inMemoryStore.ts`).
6. Restringir explícitamente `algorithms` en `jwt.verify` (M-07).

### FASE 4 — MONITORIZACIÓN
1. Alertas sobre patrones de fuerza bruta / múltiples fallos de login o MFA.
2. Alertas sobre accesos administrativos masivos a la bóveda (`vault_view` a gran volumen en poco tiempo).
3. Revisión periódica de `AuditLog` con retención adecuada y protección contra manipulación (logs inmutables, como exige la especificación).

### FASE 5 — SEGURIDAD CONTINUA
1. `npm audit`/Dependabot periódico sobre dependencias (Prisma 5.4.1, Express 4.21.2, etc. — revisar CVEs conocidos según se publiquen).
2. Rotación periódica de `JWT_SECRET`/`VAULT_MASTER_SECRET` con proceso de re-cifrado documentado.
3. Pruebas de penetración periódicas antes de cada release mayor.
4. Backups cifrados y verificados, con clave de backup independiente de `VAULT_MASTER_SECRET`.

---

## 15. CHECKLIST FINAL ANTES DE PRODUCCIÓN

- [ ] Secretos (`JWT_SECRET`, `JWT_REFRESH_SECRET`, `VAULT_MASTER_SECRET`) confirmados como valores fuertes y únicos en Render, sin fallback en código.
- [ ] Admin por defecto eliminado del código; cuenta inicial creada por seed manual con contraseña aleatoria.
- [ ] CORS restringido a orígenes de confianza explícitos.
- [ ] IDOR de "compartir bóveda" corregido y probado.
- [ ] Rate limiting activo en todos los endpoints de autenticación.
- [ ] Auditoría de visualización/copia de contraseñas implementada.
- [ ] Scripts operativos peligrosos fuera del árbol de despliegue.
- [ ] Ningún secreto se escribe en logs bajo ninguna circunstancia.
- [ ] Token de reseteo de contraseña fuera de la URL visible.
- [ ] HSTS y CSP endurecidos para producción.
- [ ] Cifrado de bóveda migrado a clave por usuario derivada con Argon2id (o plan de migración documentado y priorizado).
- [ ] `npm audit` limpio de vulnerabilidades explotables conocidas.

---

*Fin del informe. No se han realizado cambios en el código como parte de esta auditoría.*
