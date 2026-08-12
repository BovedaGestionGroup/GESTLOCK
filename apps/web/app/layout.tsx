import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Gestor de Contraseñas Empresarial',
  description: 'Gestión segura de credenciales empresariales',
  icons: {
    icon: '/favicon.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}
