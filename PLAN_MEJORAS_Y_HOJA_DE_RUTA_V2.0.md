# PLAN DE MEJORAS Y HOJA DE RUTA — GESTLOCK V2.0

**Fecha de Redacción:** 24 de agosto de 2026  
**Estado Actual del Sistema:** Versión 1.0.1 (Desplegada en Render con Puntuación de Ciberseguridad 92/100)  
**Objetivo:** Especificar la arquitectura técnica y funcional de las nuevas características planificadas para la Versión 2.0 de GESTLOCK.

---

## 1. REVISIÓN DEL ESTADO ACTUAL DEL PROYECTO (v1.0.1)

Actualmente, **GESTLOCK v1.0.1** cuenta con una base sólida y segura:
- **Backend:** Express API en Node.js, Prisma ORM con PostgreSQL en Render.
- **Frontend:** Next.js (React) con Tailwind CSS.
- **Seguridad:** Argon2id para hashes de usuarios, AES-256-GCM para la bóveda, JWT de acceso (15m) + refresh tokens revocables en BD (7d), CORS con lista blanca estricta, Rate Limiting (20 req/15m auth, 5 req/15m MFA), HSTS, CSP y auditoría completa de visualizaciones (`vault_view`).
- **Puntuación de Ciberseguridad:** **92 / 100 🟢 (Apto para Producción)**.

---

## 2. ESPECIFICACIÓN DE MEJORAS Y NUEVAS FUNCIONALIDADES (VERSIÓN 2.0)

### 📌 1. Cifrado por Usuario en Servidor (Opción 1 - C-03)
* **Objetivo:** Eliminar la dependencia de una sal global estática y lograr el aislamiento criptográfico completo entre usuarios.
* **Diseño Técnico:**
  1. Añadir el campo `userSalt String @default(uuid())` en el modelo `User` de Prisma.
  2. Al crear un usuario, el sistema genera automáticamente un `userSalt` único de 32 bytes.
  3. La clave de cifrado de cada entrada de bóveda se derivará dinámicamente mediante:
     $$\text{ClaveUsuario} = \text{scryptSync}(\text{VAULT\_MASTER\_SECRET}, \text{user.userSalt}, 32)$$
  4. **Beneficio:** Si la sal o entrada de un usuario sufriera una fuga hipotética, el resto de usuarios permanece criptográficamente aislado e inalcanzable.

---

### 🔍 2. Buscador de Usuarios en el Panel de Administración
* **Objetivo:** Facilitar la gestión de cuentas en organizaciones con un gran volumen de empleados.
* **Diseño Técnico:**
  1. **Backend:** Actualizar el endpoint `GET /admin/users` para aceptar el parámetro opcional `?search=...` y filtrar por campos `email` y `role`.
  2. **Frontend:** Añadir un campo de búsqueda en tiempo real con icono de lupa en la tabla de gestión de usuarios (`apps/web/app/page.tsx`).

---

### ✉️ 3. Corrección del Estilo del Botón en Emails de Recuperación *(Ya Desplegado en v1.0.1)*
* **Problema anterior:** El botón usaba `background: linear-gradient(...)` con `color: white`, lo que provocaba que en ciertos clientes de correo (Outlook, Gmail dark mode) el texto apareciera blanco sobre fondo blanco.
* **Solución aplicada:** Se ha actualizado el código en `apps/api/src/email.ts` con estilos HTML inline de alta compatibilidad:
  ```html
  <a href="${resetUrl}" target="_blank" style="background-color:#0d9488;color:#ffffff !important;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px;display:inline-block;border:none;">
    <span style="color:#ffffff !important;">Restablecer contraseña</span>
  </a>
  ```

---

### 🔑 4. Protocolo Seguro de Recuperación de Contraseña con Aprobación del Admin ("Olvidé mi contraseña")
* **Objetivo:** Evitar que un usuario pueda resetear su contraseña de forma autónoma sin el conocimiento y autorización de la empresa.
* **Flujo de Trabajo:**
  1. **Solicitud del usuario:** En la pantalla de Login, se añade el enlace *"¿Olvidaste tu contraseña?"*. Al pulsar, el usuario introduce su correo corporativo.
  2. **Registro de solicitud:** El backend crea un registro en el modelo `PasswordResetRequest` con estado `PENDING`.
  3. **Notificación al Administrador:** El sistema envía un correo electrónico automático a `info@gestiongroup.es` notificando: *"El usuario X ha solicitado restablecer su contraseña"*.
  4. **Aprobación/Rechazo:** El correo del admin (y el panel de control) incluye dos botones de acción directa: **[Aprobar Solicitud]** y **[Rechazar Solicitud]**.
  5. **Generación y Envío:** Si el Administrador aprueba la solicitud, el sistema genera automáticamente el token seguro de un solo uso y envía por correo al usuario el enlace para definir su nueva contraseña.

---

### 🛡️ 5. Preservación de Bóveda tras Eliminación o Desactivación de Usuarios
* **Objetivo:** Impedir la pérdida accidental de credenciales críticas de la empresa cuando un empleado deja la organización.
* **Diseño Técnico:**
  1. **Desactivación en lugar de borrado:** Añadir el campo `isActive Boolean @default(true)` en el modelo `User`. Un usuario desactivado no puede iniciar sesión ni refrescar tokens.
  2. **Eliminación de Cascade Delete:** Eliminar la restricción `onDelete: Cascade` en la relación entre `User` y `VaultEntry`.
  3. **Reasignación de Bóveda:** En caso de eliminación física de un usuario, sus entradas de bóveda corporativas son reasignadas automáticamente a la cuenta del Administrador (`info@gestiongroup.es`), asegurando que ningún secreto empresarial se borre.

---

### 📊 6. Exportación de Bóveda a Excel Cifrado con Registro de IP e Historial
* **Objetivo:** Permitir copias de seguridad de la bóveda en un formato estructurado (Excel) pero fuertemente protegido contra accesos no autorizados.
* **Diseño Técnico:**
  1. **Generación del archivo Excel:** Uso de la librería `exceljs` para construir una hoja de cálculo formateada como tabla con las columnas: `Nombre`, `URL`, `Usuario`, `Contraseña`, `Notas`, `Fecha de Creación`.
  2. **Cifrado del archivo:** Al pulsar *"Exportar Bóveda (Excel Cifrado)"*, el sistema genera una clave aleatoria única de 16 caracteres. El Excel se cifra con esta clave usando algoritmo estándar AES.
  3. **Visualización de la clave:** La clave se le muestra al usuario por pantalla en un modal destacado **una única vez** para que pueda abrir el archivo.
  4. **Auditoría e Historial de Exportación:**
     - Cada exportación genera un evento `vault_export` en `AuditLog`.
     - Se registra obligatoriamente: `userId`, `email`, `timestamp` e `ipAddress` del cliente.
     - Se añade la pestaña **"Historial de Exportaciones"** en el panel de auditoría para consultar cuándo y desde qué IP se descargaron copias de seguridad.

---

## 3. CRONOGRAMA ESTIMADO PARA LA VERSIÓN 2.0

| Hito / Característica | Complejidad | Estimación |
|---|---|---|
| Cifrado por Usuario (Opción 1) | Media | 1 Día |
| Buscador de Usuarios en Admin | Baja | 0.5 Días |
| Protocolo de Recuperación con Aprobación | Media | 1.5 Días |
| Preservación de Bóveda al dar de baja | Media | 1 Día |
| Exportación Excel Cifrado + Historial e IP | Media-Alta | 2 Días |
| **Total Estimado v2.0** | | **6 Días de Desarrollo** |
