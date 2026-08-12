import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: Number(process.env.SMTP_PORT) || 587,
  secure: Number(process.env.SMTP_PORT) === 465, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

export async function sendVerificationEmail(to: string, code: string) {
  // If SMTP is not configured, just log it for development purposes
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log(`[DEV MODE] Mock email to ${to}: Verification code is ${code}`);
    return;
  }

  const mailOptions = {
    from: `"Gestlock" <${process.env.SMTP_USER}>`,
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
  };

  await transporter.sendMail(mailOptions);
}

export async function sendPasswordResetEmail(to: string, resetUrl: string) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log(`[DEV MODE] Mock password reset email to ${to}: ${resetUrl}`);
    return;
  }

  const mailOptions = {
    from: `"Gestlock" <${process.env.SMTP_USER}>`,
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
  };

  await transporter.sendMail(mailOptions);
}
