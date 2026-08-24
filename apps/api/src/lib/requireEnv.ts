/**
 * requireEnv — Lee una variable de entorno obligatoria.
 * Si no existe, lanza un error y el proceso NO arranca.
 * Nunca usar valores por defecto (fallbacks) para secretos.
 */
export function requireEnv(key: string): string {
  const value = process.env[key];
  if (!value || value.trim() === '') {
    throw new Error(
      `[STARTUP ERROR] Required environment variable "${key}" is not set. ` +
        'The application cannot start without it. ' +
        'Set it in your .env file (development) or in the Render dashboard (production).',
    );
  }
  return value;
}
