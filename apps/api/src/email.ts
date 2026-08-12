import { Resend } from 'resend';

// Initialize Resend with API key (can use SMTP_PASS if configured as Resend SMTP)
const resendApiKey = process.env.RESEND_API_KEY || (process.env.SMTP_USER === 'resend' ? process.env.SMTP_PASS : undefined);
const resend = resendApiKey ? new Resend(resendApiKey) : null;
const fromEmail = process.env.SMTP_USER === 'resend' ? 'info@gestiongroup.es' : process.env.SMTP_USER || 'info@gestiongroup.es';

export async function sendVerificationEmail(to: string, code: string) {
  // If SMTP is not configured, just log it for development purposes
  if (!resend) {
    console.log(`[DEV MODE] Mock email to ${to}: Verification code is ${code}`);
    return;
  }

  const { error } = await resend.emails.send({
    from: `Gestlock <${fromEmail}>`,
    to,
    subject: 'Tu código de verificación de Gestlock',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0d9488;">Bienvenido a Gestlock</h2>
        <p>Gracias por registrarte. Para completar tu registro y acceder a la plataforma, por favor utiliza el siguiente código de verificación:</p>
        <div style="background-color: #f1f5f9; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
          <h1 style="color: #0f172a; letter-spacing: 5px; margin: 0;">${code}</h1>
        </div>
        <p>Si no has solicitado este registro, puedes ignorar este correo.</p>
        <p style="color: #64748b; font-size: 12px; margin-top: 40px;">El equipo de Gestion Group</p>
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
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #0d9488;">Restablecer contraseña</h2>
        <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en Gestlock.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" style="background: linear-gradient(to right, #14b8a6, #06b6d4); color: white; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 16px;">
            Restablecer contraseña
          </a>
        </div>
        <p style="color: #64748b; font-size: 13px;">Este enlace expirará en 1 hora. Si no solicitaste este cambio, ignora este correo.</p>
        <p style="color: #64748b; font-size: 12px; margin-top: 40px;">El equipo de Gestion Group</p>
      </div>
    `,
  });

  if (error) {
    throw new Error(error.message);
  }
}
