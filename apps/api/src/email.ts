import { Resend } from 'resend';

const resendApiKey = process.env.RESEND_API_KEY || (process.env.SMTP_USER === 'resend' ? process.env.SMTP_PASS : undefined);
const resend = resendApiKey ? new Resend(resendApiKey) : null;
const fromEmail = 'info@gestiongroup.es'; // Forced to verified domain

const LOGO_GG = 'https://gestor-web-ikec.onrender.com/logo.png';
const LOGO_GL = 'https://gestor-web-ikec.onrender.com/gestlock-logo.png.png';

const emailHeader = `
  <div style="display:table;width:100%;background-color:#0b1121;padding:20px;border-radius:8px 8px 0 0;box-sizing:border-box;">
    <div style="display:table-cell;vertical-align:middle;">
      <img src="${LOGO_GG}" alt="Gestion Group" style="height:40px;object-fit:contain;vertical-align:middle;">
    </div>
    <div style="display:table-cell;vertical-align:middle;text-align:right;">
      <img src="${LOGO_GL}" alt="Gestlock" style="height:40px;object-fit:contain;vertical-align:middle;">
    </div>
  </div>
`;

const emailFooter = `
  <p style="color:#64748b;font-size:12px;margin-top:40px;border-top:1px solid #e2e8f0;padding-top:16px;">
    El equipo de Gestion Group
  </p>
`;

export async function sendVerificationEmail(to: string, code: string) {
  if (!resend) {
    console.log(`[DEV MODE] Mock email to ${to}: Verification code is ${code}`);
    return;
  }

  const { error } = await resend.emails.send({
    from: `Gestlock <${fromEmail}>`,
    to,
    subject: 'Tu código de verificación de Gestlock',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
        ${emailHeader}
        <div style="padding:24px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px;">
          <h2 style="color:#0d9488;margin-top:0;">Bienvenido a Gestlock</h2>
          <p>Gracias por registrarte. Para completar tu registro y acceder a la plataforma, utiliza el siguiente código de verificación:</p>
          <div style="background-color:#f1f5f9;padding:20px;border-radius:8px;text-align:center;margin:20px 0;">
            <h1 style="color:#0f172a;letter-spacing:8px;margin:0;font-size:36px;">${code}</h1>
          </div>
          <p>Si no has solicitado este registro, puedes ignorar este correo.</p>
          ${emailFooter}
        </div>
      </div>
    `,
  });

  if (error) {
    throw new Error(error.message);
  }
}

export async function sendPasswordResetEmail(to: string, resetUrl: string) {
  if (!resend) {
    console.log(`[DEV MODE] Mock password reset email to ${to}: ${resetUrl}`);
    return;
  }

  const { error } = await resend.emails.send({
    from: `Gestlock <${fromEmail}>`,
    to,
    subject: 'Restablecer tu contraseña de Gestlock',
    html: `
      <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
        ${emailHeader}
        <div style="padding:24px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px;">
          <h2 style="color:#0d9488;margin-top:0;">Restablecer contraseña</h2>
          <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en Gestlock.</p>
          <div style="text-align:center;margin:30px 0;">
            <a href="${resetUrl}" style="background:linear-gradient(to right,#14b8a6,#06b6d4);color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px;">
              Restablecer contraseña
            </a>
          </div>
          <p style="color:#64748b;font-size:13px;">Este enlace expirará en 1 hora. Si no solicitaste este cambio, ignora este correo.</p>
          ${emailFooter}
        </div>
      </div>
    `,
  });

  if (error) {
    throw new Error(error.message);
  }
}
