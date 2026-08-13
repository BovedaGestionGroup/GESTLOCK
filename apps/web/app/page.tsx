'use client';

import { useEffect, useState } from 'react';
import * as xlsx from 'xlsx';

type User = {
  id: string;
  email: string;
  role: string;
};

type VaultEntry = {
  id: string;
  userId: string;
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
  const [mode, setMode] = useState<'login' | 'register' | 'verify'>('login');
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
  const [verificationCode, setVerificationCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showEntryPassword, setShowEntryPassword] = useState(false);
  const [resetToken, setResetToken] = useState('');
  const [resetEmail, setResetEmail] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');

  // Estados para Importación Excel
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importWorkbook, setImportWorkbook] = useState<xlsx.WorkBook | null>(null);
  const [importSheets, setImportSheets] = useState<string[]>([]);
  const [selectedSheet, setSelectedSheet] = useState<string>('');
  const [sheetData, setSheetData] = useState<any[]>([]);
  const [sheetHeaders, setSheetHeaders] = useState<string[]>([]);
  const [columnMap, setColumnMap] = useState<Record<string, string>>({
    name: '', url: '', username: '', password: '', notes: ''
  });
  const [selectedRows, setSelectedRows] = useState<Set<number>>(new Set());
  const [isImporting, setIsImporting] = useState(false);
  
  const [visiblePasswords, setVisiblePasswords] = useState<Record<string, boolean>>({});
  const [historyEntryId, setHistoryEntryId] = useState<string | null>(null);
  const [historyLogs, setHistoryLogs] = useState<any[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [editingEntryId, setEditingEntryId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<VaultEntry>>({});

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
    // Handle password reset link from email
    const params = new URLSearchParams(window.location.search);
    const rt = params.get('resetToken');
    const re = params.get('email');
    if (rt && re) {
      setResetToken(rt);
      setResetEmail(re);
      setMode('login'); // will show reset form instead
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
        if (response.status === 403 && data.message.includes('not verified')) {
          setMode('verify');
          setMessage('Por favor, introduce el código de verificación que enviamos a tu correo.');
          return;
        }
        throw new Error(data.message || 'Error de autenticación');
      }

      if (mode === 'register') {
        setMode('verify');
        setMessage('Usuario registrado. Revisa tu correo para obtener el código de verificación.');
      } else {
        localStorage.setItem('accessToken', data.accessToken);
        localStorage.setItem('refreshToken', data.refreshToken);
        setUser(data.user);
        setMessage('Inicio de sesión correcto');
        setEmail('');
        setPassword('');
        setConfirmPassword('');
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleVerifyEmail = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage('');
    try {
      const response = await fetch(`${API_BASE_URL}/auth/verify-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code: verificationCode }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Error de verificación');
      
      localStorage.setItem('accessToken', data.accessToken);
      localStorage.setItem('refreshToken', data.refreshToken);
      setUser(data.user);
      setMessage('Correo verificado. Sesión iniciada correctamente.');
      setEmail('');
      setPassword('');
      setConfirmPassword('');
      setVerificationCode('');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleResetPassword = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage('');
    if (newPassword !== confirmNewPassword) {
      setMessage('Las contraseñas no coinciden');
      return;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: resetToken, email: resetEmail, newPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'Error al restablecer');
      setMessage('¡Contraseña restablecida! Ya puedes iniciar sesión.');
      setResetToken('');
      setResetEmail('');
      setNewPassword('');
      setConfirmNewPassword('');
      window.history.replaceState({}, '', window.location.pathname);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleDeleteUser = async (targetId: string, targetEmail: string) => {
    if (!confirm(`¿Seguro que quieres eliminar al usuario ${targetEmail}? Esta acción no se puede deshacer.`)) return;
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users/${targetId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'No se pudo eliminar');
      setMessage(`Usuario ${targetEmail} eliminado correctamente`);
      await loadAdminUsers();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleSendResetPassword = async (targetId: string, targetEmail: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users/${targetId}/send-reset-password`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'No se pudo enviar');
      setMessage(`Correo de restablecimiento enviado a ${targetEmail}`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  const handleVerifyUser = async (targetId: string, targetEmail: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users/${targetId}/verify`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.message || 'No se pudo verificar');
      setMessage(`Usuario ${targetEmail} verificado correctamente`);
      await loadAdminUsers();
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
    setHistoryEntryId(null);
    setHistoryLogs([]);
    setEditingEntryId(null);
    setEditForm({});
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

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setImportFile(file);
    const reader = new FileReader();
    reader.onload = (e) => {
      const data = e.target?.result;
      if (data) {
        const wb = xlsx.read(data, { type: 'array' });
        setImportWorkbook(wb);
        setImportSheets(wb.SheetNames);
        if (wb.SheetNames.length > 0) {
          handleSheetSelect(wb, wb.SheetNames[0]);
        }
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleSheetSelect = (wb: xlsx.WorkBook, sheetName: string) => {
    setSelectedSheet(sheetName);
    const ws = wb.Sheets[sheetName];
    const data = xlsx.utils.sheet_to_json<any>(ws, { header: 1 }); // read as array of arrays
    if (data.length > 0) {
      const headers = data[0] as string[];
      const rows = data.slice(1).map(row => {
        const rowObj: any = {};
        headers.forEach((h, i) => {
          rowObj[h] = row[i];
        });
        return rowObj;
      });
      setSheetHeaders(headers);
      setSheetData(rows);
      setSelectedRows(new Set(rows.map((_, i) => i)));
      
      const guessCol = (keywords: string[]) => headers.find(h => keywords.some(k => typeof h === 'string' && h.toLowerCase().includes(k))) || '';
      setColumnMap({
        name: guessCol(['nombre', 'comercializadora', 'cliente', 'admin']),
        url: guessCol(['url', 'link', 'enlace']),
        username: guessCol(['usuario', 'mail', 'email', 'correo', 'extension', 'admins']),
        password: guessCol(['contraseña', 'password', 'pass', 'clave']),
        notes: guessCol(['observacion', 'tipo', 'firma', 'nota', 'ubicacion'])
      });
    } else {
      setSheetHeaders([]);
      setSheetData([]);
      setSelectedRows(new Set());
    }
  };

  const handleToggleRow = (index: number) => {
    const newSelected = new Set(selectedRows);
    if (newSelected.has(index)) {
      newSelected.delete(index);
    } else {
      newSelected.add(index);
    }
    setSelectedRows(newSelected);
  };

  const handleImport = async () => {
    if (!user) return;
    setIsImporting(true);
    setMessage('Importando...');
    let successCount = 0;
    let errorCount = 0;

    for (let i = 0; i < sheetData.length; i++) {
      if (!selectedRows.has(i)) continue;
      const row = sheetData[i];
      
      const entryPayload = {
        name: String(row[columnMap.name] || `Importado - ${new Date().toLocaleDateString()}`),
        url: String(row[columnMap.url] || ''),
        username: String(row[columnMap.username] || ''),
        password: String(row[columnMap.password] || ''),
        notes: String(row[columnMap.notes] || '')
      };

      if (!entryPayload.name || (!entryPayload.password && !entryPayload.username)) {
        errorCount++;
        continue;
      }

      try {
        const response = await fetch(`${API_BASE_URL}/vault/entries`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
          body: JSON.stringify(entryPayload),
        });
        if (response.ok) {
          successCount++;
        } else {
          errorCount++;
        }
      } catch {
        errorCount++;
      }
    }

    setMessage(`Importación finalizada: ${successCount} correctos, ${errorCount} errores.`);
    setIsImporting(false);
    await loadEntries(search);
  };

  const togglePassword = (id: string) => {
    setVisiblePasswords(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const copyPassword = (password: string) => {
    navigator.clipboard.writeText(password);
    setMessage('Contraseña copiada al portapapeles');
    setTimeout(() => setMessage(''), 3000);
  };

  const viewHistory = async (entryId: string) => {
    if (historyEntryId === entryId) {
      setHistoryEntryId(null);
      return;
    }
    setHistoryEntryId(entryId);
    setIsLoadingHistory(true);
    setHistoryLogs([]);
    try {
      const response = await fetch(`${API_BASE_URL}/vault/entries/${entryId}/history`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setHistoryLogs(data.logs);
      } else {
        setMessage('Error al cargar historial');
      }
    } catch (error) {
      console.error(error);
      setMessage('Error al cargar historial');
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const startEdit = (entry: VaultEntry) => {
    setEditingEntryId(entry.id);
    setEditForm({ name: entry.name, url: entry.url, username: entry.username, password: entry.password, notes: entry.notes });
  };

  const cancelEdit = () => {
    setEditingEntryId(null);
    setEditForm({});
  };

  const saveEdit = async (entryId: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/vault/entries/${entryId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify(editForm),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.message || 'Error al actualizar');
      }
      setMessage('Entrada actualizada correctamente');
      setEditingEntryId(null);
      await loadEntries(search);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error inesperado');
    }
  };

  return (
    <main className="min-h-screen bg-slate-950 px-6 py-10 text-slate-100">
      <div className="mx-auto flex max-w-6xl flex-col gap-6">
        <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="flex flex-col sm:flex-row items-center sm:items-start gap-6">
            <img src="/logo.png" alt="Gestion Group Logo" className="h-20 w-auto object-contain mix-blend-screen" />
            <div>
              <h1 className="mt-2 text-3xl font-semibold">Gestión funcional de contraseñas</h1>
              <p className="mt-3 max-w-2xl text-slate-300">
                Autenticación, bóveda y búsqueda operativa desde el navegador.
              </p>
            </div>
          </div>
          <img src="/gestlock-logo.png.png" alt="Gestlock Logo" className="h-28 w-auto object-contain mix-blend-screen" />
        </header>

        {!user ? (
          <section className="grid gap-6 lg:grid-cols-[1fr_0.9fr]">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
              <h2 className="text-xl font-semibold">{resetToken ? 'Nueva contraseña' : 'Acceso al sistema'}</h2>
              {resetToken ? (
                <form className="mt-4 space-y-4" onSubmit={handleResetPassword}>
                  <p className="text-sm text-slate-400">Restableciendo contraseña para <strong className="text-slate-200">{resetEmail}</strong></p>
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    type="password"
                    placeholder="Nueva contraseña (mín. 12 caracteres)"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    minLength={12}
                    required
                  />
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    type="password"
                    placeholder="Confirmar nueva contraseña"
                    value={confirmNewPassword}
                    onChange={(e) => setConfirmNewPassword(e.target.value)}
                    required
                  />
                  <button className="w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white" type="submit">
                    Guardar nueva contraseña
                  </button>
                  {message ? <p className="mt-2 text-sm text-cyan-300">{message}</p> : null}
                </form>
              ) : mode === 'verify' ? (
                <form className="mt-4 space-y-4" onSubmit={handleVerifyEmail}>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      className="rounded px-3 py-2 font-medium transition-all bg-gradient-to-r from-teal-500 to-cyan-500 shadow-md shadow-cyan-900/20 text-white"
                    >
                      Verificar
                    </button>
                  </div>
                  <p className="text-sm text-slate-300">Se ha enviado un código a <strong>{email}</strong></p>
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-center text-xl tracking-[0.5em] font-mono"
                    placeholder="000000"
                    maxLength={6}
                    value={verificationCode}
                    onChange={(event) => setVerificationCode(event.target.value)}
                    autoFocus
                  />
                  {message ? <p className="text-sm text-red-400">{message}</p> : null}
                  <button className="w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white" type="submit">
                    Verificar y continuar
                  </button>
                  <button
                    type="button"
                    className="w-full text-sm text-slate-400 hover:text-white"
                    onClick={() => { setMode('login'); setMessage(''); }}
                  >
                    Volver a inicio de sesión
                  </button>
                </form>
              ) : (
              <form className="mt-4 space-y-4" onSubmit={handleAuth}>
                <div className="flex gap-2">
                  <button
                    type="button"
                    className={`rounded px-3 py-2 font-medium transition-all ${mode === 'login' ? 'bg-gradient-to-r from-teal-500 to-cyan-500 shadow-md shadow-cyan-900/20 text-white' : 'bg-slate-800 hover:bg-slate-700'}`}
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
                    className={`rounded px-3 py-2 font-medium transition-all ${mode === 'register' ? 'bg-gradient-to-r from-teal-500 to-cyan-500 shadow-md shadow-cyan-900/20 text-white' : 'bg-slate-800 hover:bg-slate-700'}`}
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
                <button className="w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white" type="submit">
                  {mode === 'login' ? 'Entrar' : 'Crear cuenta'}
                </button>
                {message ? <p className="mt-2 text-sm text-cyan-300">{message}</p> : null}
              </form>
              )}
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
                <>
                  <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                    <h2 className="text-xl font-semibold">Administración</h2>
                    <p className="mt-2 text-sm text-slate-400">Gestiona usuarios y roles desde la consola administrativa.</p>
                    <div className="mt-4 space-y-3">
                      {adminUsers.map((adminUser) => (
                        <div key={adminUser.id} className="rounded border border-slate-800 bg-slate-950/70 p-3 space-y-2">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="font-medium text-sm">{adminUser.email}</p>
                              <div className="flex items-center gap-2">
                                <p className="text-xs text-slate-400">{adminUser.mfaEnabled ? 'MFA habilitado' : 'MFA no habilitado'}</p>
                                <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${(adminUser as any).isVerified !== false ? 'bg-emerald-900/40 text-emerald-400' : 'bg-orange-900/40 text-orange-400'}`}>
                                  {(adminUser as any).isVerified !== false ? '✓ Verificado' : '⚠ Sin verificar'}
                                </span>
                              </div>
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
                          <div className="flex gap-2 flex-wrap">
                            {(adminUser as any).isVerified === false && (
                              <button
                                className="rounded bg-emerald-900/30 hover:bg-emerald-900/60 border border-emerald-900/40 px-2 py-1 text-xs text-emerald-400 transition-colors"
                                onClick={() => void handleVerifyUser(adminUser.id, adminUser.email)}
                              >
                                ✅ Verificar
                              </button>
                            )}
                            <button
                              className="flex-1 rounded bg-cyan-900/30 hover:bg-cyan-900/50 border border-cyan-900/40 px-2 py-1 text-xs text-cyan-300 transition-colors"
                              onClick={() => void handleSendResetPassword(adminUser.id, adminUser.email)}
                            >
                              🔑 Restablecer contraseña
                            </button>
                            <button
                              className="rounded bg-red-900/30 hover:bg-red-900/60 border border-red-900/40 px-2 py-1 text-xs text-red-400 transition-colors"
                              onClick={() => void handleDeleteUser(adminUser.id, adminUser.email)}
                            >
                              🗑 Eliminar
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                    <h2 className="text-xl font-semibold">Importar desde Excel</h2>
                    <p className="mt-2 text-sm text-slate-400">Selecciona un archivo Excel (.xlsx, .csv) para importar contraseñas a tu bóveda de forma masiva.</p>
                    
                    <div className="mt-4">
                      <input 
                        type="file" 
                        accept=".xlsx, .xls, .csv"
                        className="block w-full text-sm text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-cyan-900/30 file:text-cyan-300 hover:file:bg-cyan-900/50"
                        onChange={handleFileUpload}
                      />
                    </div>

                    {importWorkbook && (
                      <div className="mt-6 space-y-4">
                        <div className="flex items-center gap-3">
                          <label className="text-sm font-medium">Pestaña:</label>
                          <select 
                            className="rounded border border-slate-700 bg-slate-950 px-3 py-1.5 text-sm"
                            value={selectedSheet}
                            onChange={(e) => importWorkbook && handleSheetSelect(importWorkbook, e.target.value)}
                          >
                            {importSheets.map(sheet => (
                              <option key={sheet} value={sheet}>{sheet}</option>
                            ))}
                          </select>
                        </div>

                        {sheetHeaders.length > 0 && (
                          <div className="rounded border border-slate-700 bg-slate-950 p-4">
                            <h3 className="text-sm font-semibold mb-3">Mapeo de Columnas</h3>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-sm">
                              <div>
                                <label className="block text-slate-400 text-xs mb-1">Nombre *</label>
                                <select className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs" value={columnMap.name} onChange={e => setColumnMap({...columnMap, name: e.target.value})}>
                                  <option value="">-- Ignorar --</option>
                                  {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                                </select>
                              </div>
                              <div>
                                <label className="block text-slate-400 text-xs mb-1">URL</label>
                                <select className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs" value={columnMap.url} onChange={e => setColumnMap({...columnMap, url: e.target.value})}>
                                  <option value="">-- Ignorar --</option>
                                  {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                                </select>
                              </div>
                              <div>
                                <label className="block text-slate-400 text-xs mb-1">Usuario</label>
                                <select className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs" value={columnMap.username} onChange={e => setColumnMap({...columnMap, username: e.target.value})}>
                                  <option value="">-- Ignorar --</option>
                                  {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                                </select>
                              </div>
                              <div>
                                <label className="block text-slate-400 text-xs mb-1">Contraseña</label>
                                <select className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs" value={columnMap.password} onChange={e => setColumnMap({...columnMap, password: e.target.value})}>
                                  <option value="">-- Ignorar --</option>
                                  {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                                </select>
                              </div>
                              <div>
                                <label className="block text-slate-400 text-xs mb-1">Notas</label>
                                <select className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 text-xs" value={columnMap.notes} onChange={e => setColumnMap({...columnMap, notes: e.target.value})}>
                                  <option value="">-- Ignorar --</option>
                                  {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                                </select>
                              </div>
                            </div>
                          </div>
                        )}

                        {sheetData.length > 0 && (
                          <div className="mt-4">
                            <div className="flex justify-between items-center mb-2">
                              <h3 className="text-sm font-semibold">Vista Previa ({selectedRows.size} seleccionados de {sheetData.length})</h3>
                              <button 
                                className="text-xs text-cyan-400 hover:text-cyan-300"
                                onClick={() => setSelectedRows(selectedRows.size === sheetData.length ? new Set() : new Set(sheetData.map((_, i) => i)))}
                              >
                                {selectedRows.size === sheetData.length ? 'Desmarcar todos' : 'Marcar todos'}
                              </button>
                            </div>
                            <div className="max-h-60 overflow-y-auto rounded border border-slate-700 bg-slate-950">
                              <table className="w-full text-left text-xs">
                                <thead className="sticky top-0 bg-slate-900 shadow text-slate-400">
                                  <tr>
                                    <th className="p-2 w-10 text-center">✓</th>
                                    <th className="p-2">{columnMap.name || 'Nombre'}</th>
                                    <th className="p-2">{columnMap.username || 'Usuario'}</th>
                                    <th className="p-2">{columnMap.password || 'Contraseña'}</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800">
                                  {sheetData.map((row, i) => (
                                    <tr key={i} className="hover:bg-slate-900/50 cursor-pointer" onClick={() => handleToggleRow(i)}>
                                      <td className="p-2 text-center" onClick={(e) => e.stopPropagation()}>
                                        <input type="checkbox" checked={selectedRows.has(i)} onChange={() => handleToggleRow(i)} className="rounded border-slate-700 bg-slate-800" />
                                      </td>
                                      <td className="p-2 truncate max-w-[150px]">{row[columnMap.name] || '-'}</td>
                                      <td className="p-2 truncate max-w-[150px]">{row[columnMap.username] || '-'}</td>
                                      <td className="p-2 truncate max-w-[150px]">{row[columnMap.password] || '-'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                            <button 
                              className="mt-4 w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white" 
                              onClick={() => void handleImport()}
                              disabled={isImporting || selectedRows.size === 0}
                            >
                              {isImporting ? 'Procesando...' : `Importar ${selectedRows.size} registros`}
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </>
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
                  <button className="w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white" type="submit">
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
                      {editingEntryId === entry.id ? (
                        <div className="space-y-3">
                          <input className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm" placeholder="Nombre" value={editForm.name || ''} onChange={(e) => setEditForm({...editForm, name: e.target.value})} />
                          <input className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm" placeholder="URL" value={editForm.url || ''} onChange={(e) => setEditForm({...editForm, url: e.target.value})} />
                          <input className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm" placeholder="Usuario" value={editForm.username || ''} onChange={(e) => setEditForm({...editForm, username: e.target.value})} />
                          <input className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm" placeholder="Contraseña" value={editForm.password || ''} onChange={(e) => setEditForm({...editForm, password: e.target.value})} />
                          <textarea className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm" placeholder="Notas" rows={2} value={editForm.notes || ''} onChange={(e) => setEditForm({...editForm, notes: e.target.value})} />
                          <div className="flex gap-2 mt-2">
                            <button className="rounded bg-gradient-to-r from-teal-500 to-cyan-500 px-3 py-1.5 text-xs font-medium text-white shadow" onClick={() => saveEdit(entry.id)}>Guardar</button>
                            <button className="rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs text-slate-300" onClick={cancelEdit}>Cancelar</button>
                          </div>
                        </div>
                      ) : (
                        <>
                          <div className="flex items-start justify-between gap-3">
                            <div>
                              <h3 className="font-semibold">{entry.name}</h3>
                              <p className="mt-1 text-sm text-slate-400">{entry.url}</p>
                            </div>
                            <span className="rounded bg-cyan-900/50 px-2 py-1 text-xs text-cyan-300">{entry.username}</span>
                          </div>
                          <p className="mt-3 text-sm text-slate-300">Usuario: {entry.username}</p>
                          <div className="mt-1 flex items-center gap-2">
                            <span className="text-sm text-slate-300">Contraseña:</span>
                            <span className="font-mono text-sm tracking-wider bg-slate-900 px-2 py-0.5 rounded text-cyan-100">
                              {visiblePasswords[entry.id] ? entry.password : '••••••••'}
                            </span>
                            <button 
                              className="text-xs text-slate-400 hover:text-cyan-300 transition-colors"
                              onClick={() => togglePassword(entry.id)}
                              title={visiblePasswords[entry.id] ? "Ocultar" : "Mostrar"}
                            >
                              {visiblePasswords[entry.id] ? '🙈' : '👁️'}
                            </button>
                            <button 
                              className="text-xs text-slate-400 hover:text-cyan-300 transition-colors"
                              onClick={() => copyPassword(entry.password)}
                              title="Copiar contraseña"
                            >
                              📋
                            </button>
                          </div>
                          {entry.notes ? <p className="mt-1 text-sm text-slate-400">Notas: {entry.notes}</p> : null}
                          <div className="mt-4 flex flex-wrap items-center gap-2">
                            {user.role === 'admin' ? (
                              <>
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
                                <button className="rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 px-3 py-1.5 text-sm font-medium shadow-md shadow-cyan-900/20 transition-all text-white" onClick={() => void handleShareEntry(entry.id)}>
                                  Compartir
                                </button>
                              </>
                            ) : null}
                            {(user.role === 'admin' || user.id === entry.userId) ? (
                              <button 
                                className="rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-sm font-medium transition-all text-slate-200"
                                onClick={() => startEdit(entry)}
                              >
                                Editar
                              </button>
                            ) : null}
                            {(user.role === 'admin' || user.role === 'auditor') ? (
                              <button 
                                className="rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 text-sm font-medium transition-all text-slate-200"
                                onClick={() => viewHistory(entry.id)}
                              >
                                {historyEntryId === entry.id ? 'Ocultar Historial' : 'Ver Historial'}
                              </button>
                            ) : null}
                          </div>

                          {(user.role === 'admin' || user.role === 'auditor') && historyEntryId === entry.id && (
                            <div className="mt-4 rounded bg-slate-900 border border-slate-700 p-4">
                              <h4 className="text-sm font-semibold mb-2 text-cyan-400">Historial de Cambios</h4>
                              {isLoadingHistory ? (
                                <p className="text-xs text-slate-400">Cargando...</p>
                              ) : historyLogs.length === 0 ? (
                                <p className="text-xs text-slate-400">No hay registros de auditoría para esta contraseña.</p>
                              ) : (
                                <ul className="space-y-3">
                                  {historyLogs.map(log => {
                                    let parsedDetails: any = {};
                                    try {
                                      parsedDetails = JSON.parse(log.details || '{}');
                                    } catch(e) {}
                                    
                                    return (
                                      <li key={log.id} className="text-xs border-l-2 border-slate-700 pl-3">
                                        <div className="flex items-center justify-between text-slate-300">
                                          <span className="font-semibold capitalize">{log.action.replace('_', ' ')}</span>
                                          <span className="text-slate-500">{new Date(log.createdAt).toLocaleString()}</span>
                                        </div>
                                        <div className="text-slate-400 mt-1">
                                          Usuario: <span className="text-slate-300">{log.user?.email || 'Sistema / Desconocido'}</span>
                                        </div>
                                        {parsedDetails.changes && (
                                          <div className="text-slate-400 mt-1">
                                            Cambios: <span className="text-cyan-300">{parsedDetails.changes}</span>
                                          </div>
                                        )}
                                        <div className="text-slate-500 mt-1 text-[10px]">
                                          IP: {log.ipAddress || 'N/A'}
                                        </div>
                                      </li>
                                    );
                                  })}
                                </ul>
                              )}
                            </div>
                          )}
                        </>
                      )}
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
