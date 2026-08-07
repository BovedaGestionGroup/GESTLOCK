'use client';

import { useEffect, useState } from 'react';

type User = {
  id: string;
  email: string;
  role: string;
};

type VaultEntry = {
  id: string;
  name: string;
  url: string;
  username: string;
  password: string;
  notes?: string;
  createdAt: string;
};

type AdminUser = {
  id: string;
  email: string;
  role: string;
  mfaEnabled: boolean;
  createdAt: string;
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

export default function HomePage() {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [user, setUser] = useState<User | null>(null);
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [entryForm, setEntryForm] = useState({
    name: '',
    url: '',
    username: '',
    password: '',
    notes: '',
  });
  const [message, setMessage] = useState('');
  const [search, setSearch] = useState('');
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [shareTargets, setShareTargets] = useState<Record<string, string>>({});
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showEntryPassword, setShowEntryPassword] = useState(false);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('accessToken');
    return {
      Authorization: `Bearer ${token}`,
    } as Record<string, string>;
  };

  const loadEntries = async (query = '') => {
    try {
      const response = await fetch(`${API_BASE_URL}/vault/entries${query ? `?search=${encodeURIComponent(query)}` : ''}`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) {
        throw new Error('No se pudieron cargar las entradas');
      }
      const data = await response.json();
      setEntries(data.items || []);
    } catch (error) {
      console.error(error);
    }
  };

  const loadMe = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) {
        throw new Error('No autorizado');
      }
      const data = await response.json();
      setUser(data.user);
    } catch (error) {
      setUser(null);
      localStorage.removeItem('accessToken');
      localStorage.removeItem('refreshToken');
      setMessage('Sesión expirada. Inicia sesión de nuevo.');
    }
  };

  useEffect(() => {
    const token = localStorage.getItem('accessToken');
    if (token) {
      void loadMe();
    }
  }, []);

  useEffect(() => {
    if (user) {
      void loadEntries(search);
    }
  }, [user, search]);

  const loadAdminUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) {
        throw new Error('No se pudieron cargar los usuarios');
      }
      const data = await response.json();
      setAdminUsers(data.users || []);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    if (user?.role === 'admin') {
      void loadAdminUsers();
    } else {
      setAdminUsers([]);
    }
  }, [user]);

  const handleAuth = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage('');

    if (mode === 'register' && password !== confirmPassword) {
      setMessage('Las contraseñas no coinciden');
      return;
    }

    try {
      const body = mode === 'register' ? { email, password, confirmPassword } : { email, password };
      const response = await fetch(`${API_BASE_URL}/auth/${mode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'Error de autenticación');
      }

      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);
      setUser(data.user);
      setMessage(mode === 'login' ? 'Inicio de sesión correcto' : 'Usuario registrado correctamente');
      setEmail('');
      setPassword('');
      setConfirmPassword('');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleCreateEntry = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage('');

    try {
      const response = await fetch(`${API_BASE_URL}/vault/entries`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(entryForm),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'No se pudo crear la entrada');
      }
      setEntryForm({ name: '', url: '', username: '', password: '', notes: '' });
      await loadEntries(search);
      setMessage('Entrada creada correctamente');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    setUser(null);
    setEntries([]);
    setAdminUsers([]);
    setShareTargets({});
    setMessage('Sesión cerrada');
  };

  const handleRoleChange = async (targetId: string, role: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users/${targetId}/role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ role }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'No se pudo actualizar el rol');
      }
      await loadAdminUsers();
      setMessage(`Rol actualizado para ${data.user.email}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleShareEntry = async (entryId: string) => {
    const targetUserId = shareTargets[entryId];
    if (!targetUserId) {
      setMessage('Selecciona un usuario para compartir');
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/vault/entries/${entryId}/shares`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ userId: targetUserId }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.message || 'No se pudo compartir la entrada');
      }
      setMessage('Entrada compartida correctamente');
      await loadEntries(search);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-10 text-slate-100">
      <div className="mx-auto flex max-w-6xl flex-col gap-6">
        <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
          <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Gestor empresarial</p>
          <h1 className="mt-2 text-3xl font-semibold">Gestión funcional de contraseñas</h1>
          <p className="mt-3 max-w-2xl text-slate-300">
            Autenticación, bóveda y búsqueda operativa desde el navegador.
          </p>
        </header>

        {!user ? (
          <section className="grid gap-6 lg:grid-cols-[1fr_0.9fr]">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
              <h2 className="text-xl font-semibold">Acceso al sistema</h2>
              <form className="mt-4 space-y-4" onSubmit={handleAuth}>
                <div className="flex gap-2">
                  <button
                    type="button"
                    className={`rounded px-3 py-2 ${mode === 'login' ? 'bg-cyan-600' : 'bg-slate-800'}`}
                    onClick={() => {
                      setMode('login');
                      setConfirmPassword('');
                      setMessage('');
                    }}
                  >
                    Iniciar sesión
                  </button>
                  <button
                    type="button"
                    className={`rounded px-3 py-2 ${mode === 'register' ? 'bg-cyan-600' : 'bg-slate-800'}`}
                    onClick={() => {
                      setMode('register');
                      setMessage('');
                    }}
                  >
                    Registrarse
                  </button>
                </div>

                <input
                  className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                  placeholder="Correo corporativo"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
                <div className="relative">
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Contraseña"
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                  />
                  <button
                    type="button"
                    className="absolute right-2 top-2 text-xs text-slate-400"
                    onClick={() => setShowPassword((prev) => !prev)}
                  >
                    {showPassword ? 'Ocultar' : 'Mostrar'}
                  </button>
                </div>
                {mode === 'register' ? (
                  <div className="relative">
                    <input
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Repetir contraseña"
                      value={confirmPassword}
                      onChange={(event) => setConfirmPassword(event.target.value)}
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-2 text-xs text-slate-400"
                      onClick={() => setShowPassword((prev) => !prev)}
                    >
                      {showPassword ? 'Ocultar' : 'Mostrar'}
                    </button>
                  </div>
                ) : null}
                <button className="w-full rounded bg-cyan-600 px-3 py-2 font-semibold" type="submit">
                  {mode === 'login' ? 'Entrar' : 'Crear cuenta'}
                </button>
              </form>
              {message ? <p className="mt-4 text-sm text-cyan-300">{message}</p> : null}
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
              <h2 className="text-xl font-semibold">Qué puedes hacer ahora</h2>
              <ul className="mt-4 space-y-2 text-sm text-slate-300">
                <li>• Registrar un usuario nuevo</li>
                <li>• Iniciar sesión con JWT</li>
                <li>• Guardar credenciales en la bóveda</li>
                <li>• Buscar entradas por nombre, URL o usuario</li>
              </ul>
            </div>
          </section>
        ) : (
          <section className="grid gap-6 lg:grid-cols-[0.95fr_1.05fr]">
            <div className="space-y-6">
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm uppercase tracking-[0.3em] text-cyan-400">Sesión activa</p>
                    <h2 className="text-xl font-semibold">{user.email}</h2>
                  </div>
                  <button className="rounded bg-slate-800 px-3 py-2" onClick={handleLogout}>Cerrar sesión</button>
                </div>
              </div>

              {user.role === 'admin' ? (
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                  <h2 className="text-xl font-semibold">Administración</h2>
                  <p className="mt-2 text-sm text-slate-400">Gestiona usuarios y roles desde la consola administrativa.</p>
                  <div className="mt-4 space-y-3">
                    {adminUsers.map((adminUser) => (
                      <div key={adminUser.id} className="flex items-center justify-between gap-3 rounded border border-slate-800 bg-slate-950/70 p-3">
                        <div>
                          <p className="font-medium">{adminUser.email}</p>
                          <p className="text-xs text-slate-400">{adminUser.mfaEnabled ? 'MFA habilitado' : 'MFA no habilitado'}</p>
                        </div>
                        <select
                          className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm"
                          value={adminUser.role}
                          onChange={(event) => void handleRoleChange(adminUser.id, event.target.value)}
                        >
                          <option value="user">user</option>
                          <option value="auditor">auditor</option>
                          <option value="admin">admin</option>
                        </select>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                <h2 className="text-xl font-semibold">Nueva entrada</h2>
                <form className="mt-4 space-y-3" onSubmit={handleCreateEntry}>
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    placeholder="Nombre de la credencial"
                    value={entryForm.name}
                    onChange={(event) => setEntryForm({ ...entryForm, name: event.target.value })}
                  />
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    placeholder="URL"
                    value={entryForm.url}
                    onChange={(event) => setEntryForm({ ...entryForm, url: event.target.value })}
                  />
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    placeholder="Usuario"
                    value={entryForm.username}
                    onChange={(event) => setEntryForm({ ...entryForm, username: event.target.value })}
                  />
                  <div className="relative">
                    <input
                      className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                      type={showEntryPassword ? 'text' : 'password'}
                      placeholder="Contraseña"
                      value={entryForm.password}
                      onChange={(event) => setEntryForm({ ...entryForm, password: event.target.value })}
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-2 text-xs text-slate-400"
                      onClick={() => setShowEntryPassword((prev) => !prev)}
                    >
                      {showEntryPassword ? 'Ocultar' : 'Mostrar'}
                    </button>
                  </div>
                  <textarea
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    placeholder="Notas"
                    rows={3}
                    value={entryForm.notes}
                    onChange={(event) => setEntryForm({ ...entryForm, notes: event.target.value })}
                  />
                  <button className="w-full rounded bg-cyan-600 px-3 py-2 font-semibold" type="submit">
                    Guardar entrada
                  </button>
                </form>
                {message ? <p className="mt-4 text-sm text-cyan-300">{message}</p> : null}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-semibold">Bóveda</h2>
                  <p className="text-sm text-slate-400">Entradas almacenadas para este usuario</p>
                </div>
                <input
                  className="w-48 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                  placeholder="Buscar"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                />
              </div>

              <div className="mt-4 space-y-3">
                {entries.length === 0 ? (
                  <p className="rounded border border-dashed border-slate-700 p-4 text-sm text-slate-400">
                    No hay entradas aún. Crea la primera credencial desde el formulario.
                  </p>
                ) : (
                  entries.map((entry) => (
                    <article key={entry.id} className="rounded border border-slate-800 bg-slate-950/70 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <h3 className="font-semibold">{entry.name}</h3>
                          <p className="mt-1 text-sm text-slate-400">{entry.url}</p>
                        </div>
                        <span className="rounded bg-cyan-900/50 px-2 py-1 text-xs text-cyan-300">{entry.username}</span>
                      </div>
                      <p className="mt-3 text-sm text-slate-300">Usuario: {entry.username}</p>
                      <p className="mt-1 text-sm text-slate-300">Contraseña: {entry.password}</p>
                      {entry.notes ? <p className="mt-1 text-sm text-slate-400">Notas: {entry.notes}</p> : null}
                      {user.role === 'admin' ? (
                        <div className="mt-3 flex items-center gap-2">
                          <select
                            className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm"
                            value={shareTargets[entry.id] ?? ''}
                            onChange={(event) => setShareTargets({ ...shareTargets, [entry.id]: event.target.value })}
                          >
                            <option value="">Compartir con...</option>
                            {adminUsers.filter((adminUser) => adminUser.id !== user.id).map((adminUser) => (
                              <option key={adminUser.id} value={adminUser.id}>
                                {adminUser.email}
                              </option>
                            ))}
                          </select>
                          <button className="rounded bg-cyan-600 px-3 py-2 text-sm" onClick={() => void handleShareEntry(entry.id)}>
                            Compartir
                          </button>
                        </div>
                      ) : null}
                    </article>
                  ))
                )}
              </div>
            </div>
          </section>
        )}
      </div>
    </main>
  );
}
