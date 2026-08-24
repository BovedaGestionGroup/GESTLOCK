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
  type Section = 'vault' | 'new-entry' | 'admin' | 'import';
  const [activeSection, setActiveSection] = useState<Section>('vault');
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const [mode, setMode] = useState<'login' | 'register' | 'verify' | 'forgot'>('login');
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
  const [isLoading, setIsLoading] = useState(false);

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
    // Handle password reset link from email (supports ?resetToken=... and #resetToken=...)
    const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
    const hashParams = new URLSearchParams(hash);
    const searchParams = new URLSearchParams(window.location.search);
    const rt = hashParams.get('resetToken') || searchParams.get('resetToken');
    const re = hashParams.get('email') || searchParams.get('email');
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

  const [adminSearch, setAdminSearch] = useState('');

  const loadAdminUsers = async (query = adminSearch) => {
    try {
      const url = query.trim()
        ? `${API_BASE_URL}/admin/users?search=${encodeURIComponent(query.trim())}`
        : `${API_BASE_URL}/admin/users`;
      const response = await fetch(url, {
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

  const [pendingResetRequests, setPendingResetRequests] = useState<any[]>([]);

  const loadPendingResetRequests = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/password-requests`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setPendingResetRequests(data.requests || []);
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleApproveReset = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/password-requests/${id}/approve`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      setMessage(data.message);
      await loadPendingResetRequests();
    } catch (error) {
      setMessage('Error al aprobar la solicitud');
    }
  };

  const handleRejectReset = async (id: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/password-requests/${id}/reject`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      const data = await response.json();
      setMessage(data.message);
      await loadPendingResetRequests();
    } catch (error) {
      setMessage('Error al rechazar la solicitud');
    }
  };

  const handleToggleUserStatus = async (targetId: string, currentStatus: boolean) => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users/${targetId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ isActive: !currentStatus }),
      });
      if (response.ok) {
        setMessage(`Estado del usuario actualizado correctamente`);
        await loadAdminUsers(adminSearch);
      }
    } catch (error) {
      setMessage('Error al actualizar estado');
    }
  };

  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [exportWithPassword, setExportWithPassword] = useState(true);
  const [customExportPassword, setCustomExportPassword] = useState('');
  const [showExportPassword, setShowExportPassword] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccessInfo, setExportSuccessInfo] = useState<{
    key: string | null;
    filename: string;
    isEncrypted: boolean;
  } | null>(null);
  const [copiedExportKey, setCopiedExportKey] = useState(false);
  const [exportLogs, setExportLogs] = useState<any[]>([]);

  const generateRandomExportKey = () => {
    const chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%';
    let result = '';
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    for (let i = 0; i < 16; i++) {
      result += chars[array[i] % chars.length];
    }
    setCustomExportPassword(result);
  };

  const openExportModal = () => {
    if (user?.role !== 'admin' && user?.role !== 'auditor') {
      setMessage('Solo los administradores y auditores pueden exportar la bóveda.');
      return;
    }
    if (!customExportPassword) {
      generateRandomExportKey();
    }
    setIsExportModalOpen(true);
  };

  const handleExportExcel = async () => {
    if (user?.role !== 'admin' && user?.role !== 'auditor') {
      setMessage('Solo los administradores y auditores pueden exportar la bóveda.');
      return;
    }
    try {
      setIsExporting(true);
      setMessage('Generando archivo Excel (.xlsx)...');

      const payload: { password?: string; encrypt?: boolean } = {};
      if (exportWithPassword) {
        if (customExportPassword.trim()) {
          payload.password = customExportPassword.trim();
        }
      } else {
        payload.password = '';
        payload.encrypt = false;
      }

      const response = await fetch(`${API_BASE_URL}/vault/export-excel`, {
        method: 'POST',
        headers: {
          ...getAuthHeaders(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error('Error al generar la exportación');
      }

      const data = await response.json();
      const rawB64 = data.fileBase64 || data.fileData;
      const binaryString = window.atob(rawB64);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      const blob = new Blob([bytes], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      });
      const downloadUrl = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = downloadUrl;
      a.download = data.filename || 'boveda_gestlock.xlsx';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(downloadUrl);

      setIsExportModalOpen(false);
      setExportSuccessInfo({
        key: data.tempKey,
        filename: data.filename || 'boveda_gestlock.xlsx',
        isEncrypted: Boolean(data.tempKey),
      });
      setMessage('Archivo Excel descargado con éxito.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Error al exportar');
    } finally {
      setIsExporting(false);
    }
  };

  const loadExportLogs = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/audit-logs/exports`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        setExportLogs(data.logs || []);
      }
    } catch (error) {
      console.error(error);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_BASE_URL}/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      setMessage(data.message);
    } catch (error) {
      setMessage('Error al procesar la solicitud');
    }
  };

  useEffect(() => {
    if (user?.role === 'admin' || user?.role === 'auditor') {
      if (user?.role === 'admin') {
        void loadAdminUsers(adminSearch);
        void loadPendingResetRequests();
      }
      void loadExportLogs();
    } else {
      setAdminUsers([]);
      setPendingResetRequests([]);
      setExportLogs([]);
    }
  }, [user, adminSearch]);

  const handleAuth = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setMessage('');

    const cleanEmail = email.trim().toLowerCase();

    if (mode === 'register' && password !== confirmPassword) {
      setMessage('Las contraseñas no coinciden');
      return;
    }

    setIsLoading(true);
    try {
      const body = mode === 'register' ? { email: cleanEmail, password, confirmPassword } : { email: cleanEmail, password };
      const response = await fetch(`${API_BASE_URL}/auth/${mode}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await response.json();
      if (!response.ok) {
        const errorMsg = data.message || 'Error de autenticación';
        if (response.status === 403 && (errorMsg.includes('no verificado') || errorMsg.includes('not verified') || errorMsg.includes('verificación'))) {
          setMode('verify');
          setMessage('Tu cuenta aún no está verificada. Por favor, introduce el código de 6 dígitos que enviamos a tu correo.');
          return;
        }
        throw new Error(errorMsg);
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
    } finally {
      setIsLoading(false);
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
    setActiveSection('vault');
    setIsMobileMenuOpen(false);
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
    <main className="min-h-screen bg-slate-950 px-4 sm:px-6 py-4 sm:py-8 text-slate-100">
      <div className="mx-auto flex max-w-6xl flex-col gap-6">
        <header className="rounded-2xl border border-slate-800 bg-slate-900/80 p-4 sm:p-6 flex flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            {user && (
              <button 
                className="lg:hidden p-2 -ml-2 text-slate-400 hover:text-white"
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              >
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" /></svg>
              </button>
            )}
            <img src="/gestlock-logo.png.png" alt="Gestlock Logo" className="h-8 sm:h-12 md:h-20 w-auto object-contain mix-blend-screen" />
          </div>
          <div className="hidden sm:flex flex-1 flex-col items-center justify-center text-center">
            <h1 className="text-xl md:text-3xl font-semibold">Gestión funcional de contraseñas</h1>
          </div>
          <img src="/logo.png" alt="Gestion Group Logo" className="h-6 sm:h-10 md:h-14 w-auto object-contain mix-blend-screen" />
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
              ) : mode === 'forgot' ? (
                <form className="mt-4 space-y-4" onSubmit={handleForgotPassword}>
                  <p className="text-sm text-slate-300">Introduce tu correo corporativo. El administrador revisará y aprobará tu solicitud para enviarte un enlace de restablecimiento.</p>
                  <input
                    className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
                    type="email"
                    placeholder="Correo corporativo"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                  <button className="w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white" type="submit">
                    Solicitar restablecimiento
                  </button>
                  {message ? <p className="mt-2 text-sm text-cyan-300">{message}</p> : null}
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
                  <button
                    className="w-full rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 transition-all px-3 py-2 font-semibold shadow-lg shadow-cyan-900/20 text-white disabled:opacity-60 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                    type="submit"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <>
                        <svg className="animate-spin h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                        </svg>
                        {mode === 'login' ? 'Entrando...' : 'Creando cuenta...'}
                      </>
                    ) : (
                      mode === 'login' ? 'Entrar' : 'Crear cuenta'
                    )}
                  </button>

                  {mode === 'login' && (
                    <div className="text-center pt-2">
                      <button
                        type="button"
                        className="text-xs text-cyan-400 hover:underline"
                        onClick={() => { setMode('forgot' as any); setMessage(''); }}
                      >
                        ¿Olvidaste tu contraseña?
                      </button>
                    </div>
                  )}
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
          <div className="flex flex-col lg:flex-row gap-6 items-start">
            {/* Menú Lateral / Móvil */}
            <aside className={`w-full lg:w-64 flex-shrink-0 transition-all duration-300 ${isMobileMenuOpen ? 'block' : 'hidden lg:block'}`}>
              <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-5 space-y-6 lg:sticky lg:top-6">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-cyan-400 mb-1">Sesión activa</p>
                  <h2 className="text-sm font-semibold truncate" title={user.email}>{user.email}</h2>
                </div>
                
                <nav className="space-y-1.5">
                  <button 
                    onClick={() => { setActiveSection('vault'); setIsMobileMenuOpen(false); }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${activeSection === 'vault' ? 'bg-cyan-900/40 text-cyan-300 border border-cyan-800/50' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
                  >
                    🔐 Mi Bóveda
                  </button>
                  <button 
                    onClick={() => { setActiveSection('new-entry'); setIsMobileMenuOpen(false); }}
                    className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${activeSection === 'new-entry' ? 'bg-cyan-900/40 text-cyan-300 border border-cyan-800/50' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
                  >
                    ➕ Nueva Entrada
                  </button>
                  {user.role === 'admin' && (
                    <>
                      <div className="pt-4 pb-1">
                        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Admin</p>
                      </div>
                      <button 
                        onClick={() => { setActiveSection('admin'); setIsMobileMenuOpen(false); }}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${activeSection === 'admin' ? 'bg-purple-900/40 text-purple-300 border border-purple-800/50' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
                      >
                        🛡️ Usuarios
                      </button>
                      <button 
                        onClick={() => { setActiveSection('import'); setIsMobileMenuOpen(false); }}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${activeSection === 'import' ? 'bg-emerald-900/40 text-emerald-300 border border-emerald-800/50' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'}`}
                      >
                        📥 Importar Excel
                      </button>
                    </>
                  )}
                </nav>
                <div className="pt-4 border-t border-slate-800">
                  <button className="w-full rounded bg-slate-800/50 hover:bg-slate-800 px-3 py-2 text-sm text-slate-300 transition-colors" onClick={handleLogout}>
                    Cerrar sesión
                  </button>
                </div>
              </div>
            </aside>

            {/* Contenido Principal */}
            <section className="flex-1 min-w-0 space-y-6">

              {/* ---- SECCIÓN ADMIN ---- */}
              {activeSection === 'admin' && user.role === 'admin' ? (
                <div className="space-y-6">
                  {/* Solicitudes de recuperación de contraseña pendientes (Fase 4) */}
                  {pendingResetRequests.length > 0 && (
                    <div className="rounded-2xl border border-amber-800/60 bg-amber-950/30 p-6">
                      <h3 className="text-lg font-semibold text-amber-300 flex items-center gap-2">
                        🔑 Solicitudes de Recuperación de Contraseña ({pendingResetRequests.length})
                      </h3>
                      <p className="mt-1 text-sm text-slate-400">Usuarios que han solicitado restablecer su contraseña.</p>
                      <div className="mt-4 space-y-3">
                        {pendingResetRequests.map((req) => (
                          <div key={req.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded border border-amber-900/50 bg-slate-950/80 p-4">
                            <div>
                              <p className="font-medium text-sm text-slate-200">{req.user?.email || 'Usuario'}</p>
                              <p className="text-xs text-slate-500">Solicitado: {new Date(req.requestedAt).toLocaleString()}</p>
                            </div>
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleApproveReset(req.id)}
                                className="rounded bg-emerald-600 hover:bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-white transition-colors"
                              >
                                Aprobar
                              </button>
                              <button
                                onClick={() => handleRejectReset(req.id)}
                                className="rounded bg-rose-600 hover:bg-rose-500 px-3 py-1.5 text-xs font-semibold text-white transition-colors"
                              >
                                Rechazar
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <h2 className="text-xl font-semibold">Administración</h2>
                      <p className="mt-1 text-sm text-slate-400">Gestiona usuarios y roles desde la consola administrativa.</p>
                    </div>
                    {/* Buscador de Usuarios */}
                    <div className="relative min-w-[240px]">
                      <input
                        type="text"
                        placeholder="Buscar por email o rol..."
                        value={adminSearch}
                        onChange={(e) => setAdminSearch(e.target.value)}
                        className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 pl-9 text-sm text-white placeholder-slate-500 focus:border-teal-500 focus:outline-none focus:ring-1 focus:ring-teal-500"
                      />
                      <svg className="absolute left-3 top-2.5 h-4 w-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
                    </div>
                  </div>
                  <div className="mt-4 space-y-3">
                    {adminUsers.map((adminUser) => (
                      <div key={adminUser.id} className="rounded border border-slate-800 bg-slate-950/70 p-4 space-y-3">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                          <div className="min-w-0">
                            <p className="font-medium text-sm truncate">{adminUser.email}</p>
                            <div className="flex flex-wrap items-center gap-2 mt-1">
                              <p className="text-xs text-slate-400">{adminUser.mfaEnabled ? 'MFA habilitado' : 'MFA no habilitado'}</p>
                              <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${(adminUser as any).isVerified !== false ? 'bg-emerald-900/40 text-emerald-400' : 'bg-orange-900/40 text-orange-400'}`}>
                                {(adminUser as any).isVerified !== false ? '✓ Verificado' : '⚠ Sin verificar'}
                              </span>
                            </div>
                          </div>
                          <select
                            className="w-full sm:w-auto rounded border border-slate-700 bg-slate-950 px-2 py-2 sm:py-1 text-sm"
                            value={adminUser.role}
                            onChange={(event) => void handleRoleChange(adminUser.id, event.target.value)}
                          >
                            <option value="user">user</option>
                            <option value="auditor">auditor</option>
                            <option value="admin">admin</option>
                          </select>
                        </div>
                        <div className="flex flex-col sm:flex-row gap-2">
                          {(adminUser as any).isVerified === false && (
                            <button
                              className="w-full sm:w-auto rounded bg-emerald-900/30 hover:bg-emerald-900/60 border border-emerald-900/40 px-3 py-2 sm:py-1 text-xs text-emerald-400 transition-colors"
                              onClick={() => void handleVerifyUser(adminUser.id, adminUser.email)}
                            >
                              ✅ Verificar
                            </button>
                          )}
                          <button
                            className="flex-1 w-full sm:w-auto rounded bg-cyan-900/30 hover:bg-cyan-900/50 border border-cyan-900/40 px-3 py-2 sm:py-1 text-xs text-cyan-300 transition-colors"
                            onClick={() => void handleSendResetPassword(adminUser.id, adminUser.email)}
                          >
                            🔑 Restablecer contraseña
                          </button>
                          <button
                            className={`w-full sm:w-auto rounded border px-3 py-2 sm:py-1 text-xs transition-colors ${(adminUser as any).isActive === false ? 'bg-emerald-900/30 hover:bg-emerald-900/60 border-emerald-900/40 text-emerald-400' : 'bg-amber-900/30 hover:bg-amber-900/60 border-amber-900/40 text-amber-400'}`}
                            onClick={() => void handleToggleUserStatus(adminUser.id, (adminUser as any).isActive !== false)}
                          >
                            {(adminUser as any).isActive === false ? '▶ Activar' : '⏸ Desactivar'}
                          </button>
                          <button
                            className="w-full sm:w-auto rounded bg-red-900/30 hover:bg-red-900/60 border border-red-900/40 px-3 py-2 sm:py-1 text-xs text-red-400 transition-colors"
                            onClick={() => void handleDeleteUser(adminUser.id, adminUser.email)}
                          >
                            🗑 Eliminar
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Historial de Exportaciones a Excel (Fase 6) */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    📊 Historial de Exportaciones a Excel
                  </h3>
                  <p className="mt-1 text-sm text-slate-400">Registro de descargas de backups cifrados con dirección IP y usuario.</p>
                  <div className="mt-4 space-y-3">
                    {exportLogs.length === 0 ? (
                      <p className="text-sm text-slate-500 italic">No se han registrado exportaciones aún.</p>
                    ) : (
                      exportLogs.map((log) => (
                        <div key={log.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 rounded border border-slate-800 bg-slate-950/70 p-4">
                          <div>
                            <p className="font-medium text-sm text-slate-200">{log.user?.email || 'Usuario'}</p>
                            <p className="text-xs text-slate-400 mt-0.5">{log.details}</p>
                          </div>
                          <div className="text-right">
                            <span className="inline-block rounded bg-teal-900/40 border border-teal-800/50 px-2 py-0.5 text-xs text-teal-300 font-mono">
                              IP: {log.ipAddress || 'Desconocida'}
                            </span>
                            <p className="text-xs text-slate-500 mt-1">{new Date(log.createdAt).toLocaleString('es-ES')}</p>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
                </div>
              ) : null}

              {/* ---- SECCIÓN IMPORTAR ---- */}
              {activeSection === 'import' && user.role === 'admin' ? (
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
                          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 text-sm">
                            <div>
                              <label className="block text-slate-400 text-xs mb-1">Nombre *</label>
                              <select className="w-full rounded border border-slate-800 bg-slate-900 px-3 py-2 sm:py-1 text-xs" value={columnMap.name} onChange={e => setColumnMap({...columnMap, name: e.target.value})}>
                                <option value="">-- Ignorar --</option>
                                {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </div>
                            <div>
                              <label className="block text-slate-400 text-xs mb-1">URL</label>
                              <select className="w-full rounded border border-slate-800 bg-slate-900 px-3 py-2 sm:py-1 text-xs" value={columnMap.url} onChange={e => setColumnMap({...columnMap, url: e.target.value})}>
                                <option value="">-- Ignorar --</option>
                                {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </div>
                            <div>
                              <label className="block text-slate-400 text-xs mb-1">Usuario</label>
                              <select className="w-full rounded border border-slate-800 bg-slate-900 px-3 py-2 sm:py-1 text-xs" value={columnMap.username} onChange={e => setColumnMap({...columnMap, username: e.target.value})}>
                                <option value="">-- Ignorar --</option>
                                {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </div>
                            <div>
                              <label className="block text-slate-400 text-xs mb-1">Contraseña</label>
                              <select className="w-full rounded border border-slate-800 bg-slate-900 px-3 py-2 sm:py-1 text-xs" value={columnMap.password} onChange={e => setColumnMap({...columnMap, password: e.target.value})}>
                                <option value="">-- Ignorar --</option>
                                {sheetHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                              </select>
                            </div>
                            <div>
                              <label className="block text-slate-400 text-xs mb-1">Notas</label>
                              <select className="w-full rounded border border-slate-800 bg-slate-900 px-3 py-2 sm:py-1 text-xs" value={columnMap.notes} onChange={e => setColumnMap({...columnMap, notes: e.target.value})}>
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
                          <div className="max-h-60 overflow-y-auto overflow-x-auto rounded border border-slate-700 bg-slate-950">
                            <table className="w-full text-left text-xs whitespace-nowrap min-w-[500px]">
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
                                      <input type="checkbox" checked={selectedRows.has(i)} onChange={() => handleToggleRow(i)} className="rounded border-slate-700 bg-slate-800 h-4 w-4" />
                                    </td>
                                    <td className="p-2 truncate max-w-[150px] sm:max-w-xs">{row[columnMap.name] || '-'}</td>
                                    <td className="p-2 truncate max-w-[150px] sm:max-w-xs">{row[columnMap.username] || '-'}</td>
                                    <td className="p-2 truncate max-w-[150px] sm:max-w-xs">{row[columnMap.password] || '-'}</td>
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
              ) : null}

              {/* ---- SECCIÓN NUEVA ENTRADA ---- */}
              {activeSection === 'new-entry' ? (
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
                      placeholder="Usuario / Email"
                      value={entryForm.username}
                      onChange={(event) => setEntryForm({ ...entryForm, username: event.target.value })}
                    />
                    <div className="relative">
                      <input
                        className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 pr-16"
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
              ) : null}

              {/* ---- SECCIÓN BÓVEDA ---- */}
              {activeSection === 'vault' ? (
                <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 space-y-6">
                  {/* Modal de Configuración de Exportación Excel */}
                  {isExportModalOpen && (
                    <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
                      <div className="bg-slate-900 border border-teal-500/40 rounded-2xl p-6 max-w-lg w-full space-y-5 shadow-2xl">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3 text-teal-400">
                            <span className="text-2xl">📊</span>
                            <h3 className="text-lg font-bold text-white">Exportar Bóveda a Excel (.xlsx)</h3>
                          </div>
                          <button
                            onClick={() => setIsExportModalOpen(false)}
                            className="text-slate-400 hover:text-white transition-colors"
                          >
                            ✕
                          </button>
                        </div>

                        <p className="text-sm text-slate-300">
                          Descarga una copia completa de tus contraseñas en formato nativo <strong>Microsoft Excel (.xlsx)</strong>.
                        </p>

                        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-4 space-y-4">
                          <label className="flex items-center gap-3 cursor-pointer select-none">
                            <input
                              type="checkbox"
                              checked={exportWithPassword}
                              onChange={(e) => setExportWithPassword(e.target.checked)}
                              className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-teal-500 focus:ring-teal-500"
                            />
                            <span className="text-sm font-medium text-slate-200">
                              🔒 Proteger archivo con contraseña (Recomendado)
                            </span>
                          </label>

                          {exportWithPassword ? (
                            <div className="space-y-3 pt-2 border-t border-slate-800/80">
                              <div className="flex items-center justify-between">
                                <label className="text-xs font-semibold text-slate-400">
                                  Contraseña de apertura del archivo Excel:
                                </label>
                                <button
                                  type="button"
                                  onClick={generateRandomExportKey}
                                  className="text-xs text-teal-400 hover:text-teal-300 transition-colors font-medium flex items-center gap-1"
                                >
                                  🎲 Generar clave aleatoria
                                </button>
                              </div>

                              <div className="relative">
                                <input
                                  type={showExportPassword ? 'text' : 'password'}
                                  value={customExportPassword}
                                  onChange={(e) => setCustomExportPassword(e.target.value)}
                                  placeholder="Escribe o genera una clave..."
                                  className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-white pr-20 font-mono focus:border-teal-500 focus:outline-none"
                                />
                                <button
                                  type="button"
                                  onClick={() => setShowExportPassword(!showExportPassword)}
                                  className="absolute right-3 top-2.5 text-xs text-slate-400 hover:text-slate-200"
                                >
                                  {showExportPassword ? 'Ocultar' : 'Ver'}
                                </button>
                              </div>

                              <p className="text-xs text-slate-400 bg-slate-900/50 p-2.5 rounded-lg border border-slate-800">
                                💡 <strong>¿Cómo funciona?</strong> Al abrir el archivo descargado en Microsoft Excel, LibreOffice o tu visor de hojas de cálculo, se te solicitará esta contraseña para desbloquear el contenido.
                              </p>
                            </div>
                          ) : (
                            <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-900/50 text-xs text-amber-300">
                              ⚠️ <strong>Aviso:</strong> El archivo se descargará en formato Excel estándar sin contraseña. Cualquiera con acceso al archivo podrá ver las credenciales.
                            </div>
                          )}
                        </div>

                        <div className="flex gap-3 pt-2">
                          <button
                            type="button"
                            onClick={() => setIsExportModalOpen(false)}
                            className="flex-1 rounded-lg border border-slate-700 hover:bg-slate-800 py-2.5 text-sm font-medium text-slate-300 transition-colors"
                          >
                            Cancelar
                          </button>
                          <button
                            type="button"
                            onClick={handleExportExcel}
                            disabled={isExporting || (exportWithPassword && !customExportPassword.trim())}
                            className="flex-1 rounded-lg bg-teal-600 hover:bg-teal-500 disabled:opacity-50 text-white py-2.5 text-sm font-semibold transition-colors flex items-center justify-center gap-2"
                          >
                            {isExporting ? (
                              <>⏳ Generando Excel...</>
                            ) : (
                              <>📥 Descargar Excel (.xlsx)</>
                            )}
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Modal de Éxito con visualización de la clave de apertura */}
                  {exportSuccessInfo && (
                    <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
                      <div className="bg-slate-900 border border-emerald-500/50 rounded-2xl p-6 max-w-md w-full space-y-4 shadow-2xl">
                        <div className="flex items-center gap-3 text-emerald-400">
                          <span className="text-2xl">✅</span>
                          <h3 className="text-lg font-bold text-white">¡Excel Descargado con Éxito!</h3>
                        </div>

                        <p className="text-sm text-slate-300">
                          Se ha guardado <strong className="text-teal-300">{exportSuccessInfo.filename}</strong> en tu equipo.
                        </p>

                        {exportSuccessInfo.isEncrypted && exportSuccessInfo.key && (
                          <div className="space-y-3">
                            <p className="text-xs text-slate-400 font-medium">
                              Contraseña necesaria para abrir tu archivo en Excel:
                            </p>
                            <div className="flex items-center gap-2 rounded-xl bg-slate-950 border border-teal-500/40 p-3">
                              <code className="text-lg font-mono tracking-wider text-teal-300 font-bold flex-1 select-all break-all">
                                {exportSuccessInfo.key}
                              </code>
                              <button
                                type="button"
                                onClick={() => {
                                  if (exportSuccessInfo.key) {
                                    navigator.clipboard.writeText(exportSuccessInfo.key);
                                    setCopiedExportKey(true);
                                    setTimeout(() => setCopiedExportKey(false), 2500);
                                  }
                                }}
                                className="rounded-lg bg-teal-600 hover:bg-teal-500 px-3 py-1.5 text-xs font-semibold text-white transition-colors"
                              >
                                {copiedExportKey ? '✓ ¡Copiada!' : '📋 Copiar'}
                              </button>
                            </div>
                            <p className="text-xs text-slate-400 bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                              📄 <strong>Instrucciones:</strong> Haz doble clic en el archivo <strong>.xlsx</strong> descargado. Cuando Microsoft Excel te solicite la clave, introduce la contraseña indicada arriba.
                            </p>
                          </div>
                        )}

                        <button
                          onClick={() => setExportSuccessInfo(null)}
                          className="w-full rounded-lg bg-teal-600 hover:bg-teal-500 text-white py-2.5 font-semibold transition-colors mt-2"
                        >
                          Entendido y Cerrar
                        </button>
                      </div>
                    </div>
                  )}

                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div>
                      <h2 className="text-xl font-semibold">Bóveda</h2>
                      <p className="text-sm text-slate-400">Entradas almacenadas para este usuario</p>
                    </div>
                    <div className="flex flex-wrap items-center gap-3">
                      <input
                        className="w-full sm:w-56 rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                        placeholder="Buscar credencial..."
                        value={search}
                        onChange={(event) => setSearch(event.target.value)}
                      />
                      {(user?.role === 'admin' || user?.role === 'auditor') && (
                        <button
                          onClick={openExportModal}
                          className="rounded bg-teal-600 hover:bg-teal-500 text-white px-3 py-2 text-sm font-semibold transition-colors flex items-center gap-2"
                        >
                          📥 Exportar Excel
                        </button>
                      )}
                    </div>
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
                              <div className="flex gap-2">
                                <button className="flex-1 rounded bg-gradient-to-r from-teal-500 to-cyan-500 px-3 py-1.5 text-sm font-medium text-white" onClick={() => void saveEdit(entry.id)}>Guardar</button>
                                <button className="flex-1 rounded border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm font-medium text-slate-300" onClick={cancelEdit}>Cancelar</button>
                              </div>
                            </div>
                          ) : (
                            <>
                              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                                <div className="min-w-0">
                                  <h3 className="font-semibold truncate">{entry.name}</h3>
                                  <p className="mt-1 text-sm text-slate-400 break-all">{entry.url}</p>
                                </div>
                                <span className="self-start sm:self-auto rounded bg-cyan-900/50 px-2 py-1 text-xs text-cyan-300 break-all">{entry.username}</span>
                              </div>
                              <p className="mt-3 text-sm text-slate-300 break-all">Usuario: {entry.username}</p>
                              <div className="mt-1 flex flex-wrap items-center gap-2">
                                <span className="text-sm text-slate-300">Contraseña:</span>
                                <span className="font-mono text-sm tracking-wider bg-slate-900 px-2 py-0.5 rounded text-cyan-100 break-all">
                                  {visiblePasswords[entry.id] ? entry.password : '••••••••'}
                                </span>
                                <button
                                  className="p-1 sm:p-0 text-xs text-slate-400 hover:text-cyan-300 transition-colors"
                                  onClick={() => togglePassword(entry.id)}
                                  title={visiblePasswords[entry.id] ? "Ocultar" : "Mostrar"}
                                >
                                  {visiblePasswords[entry.id] ? '🙈 Ocultar' : '👁 Mostrar'}
                                </button>
                              </div>
                              {entry.notes ? <p className="mt-2 text-xs text-slate-500 break-all">{entry.notes}</p> : null}
                              <div className="mt-3 flex flex-col sm:flex-row gap-2">
                                {user.role === 'admin' ? (
                                  <div className="flex gap-2 flex-wrap">
                                    <select
                                      className="rounded border border-slate-700 bg-slate-950 px-2 py-1.5 text-xs"
                                      value={shareTargets[entry.id] || ''}
                                      onChange={(e) => setShareTargets({...shareTargets, [entry.id]: e.target.value})}
                                    >
                                      <option value="">Compartir con...</option>
                                      {adminUsers.filter(u => u.id !== user.id).map(u => (
                                        <option key={u.id} value={u.id}>{u.email}</option>
                                      ))}
                                    </select>
                                    <button className="w-full sm:w-auto rounded bg-gradient-to-r from-teal-500 to-cyan-500 hover:from-teal-400 hover:to-cyan-400 px-3 py-2 sm:py-1.5 text-sm font-medium shadow-md shadow-cyan-900/20 transition-all text-white" onClick={() => void handleShareEntry(entry.id)}>
                                      Compartir
                                    </button>
                                  </div>
                                ) : null}
                                <div className="flex gap-2 w-full sm:w-auto mt-2 sm:mt-0">
                                  {(user.role === 'admin' || user.id === entry.userId) ? (
                                    <button
                                      className="flex-1 sm:flex-none rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-2 sm:py-1.5 text-sm font-medium transition-all text-slate-200"
                                      onClick={() => startEdit(entry)}
                                    >
                                      Editar
                                    </button>
                                  ) : null}
                                  {(user.role === 'admin' || user.role === 'auditor') ? (
                                    <button
                                      className="flex-1 sm:flex-none rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 px-3 py-2 sm:py-1.5 text-sm font-medium transition-all text-slate-200"
                                      onClick={() => viewHistory(entry.id)}
                                    >
                                      {historyEntryId === entry.id ? 'Ocultar Historial' : 'Ver Historial'}
                                    </button>
                                  ) : null}
                                </div>
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
              ) : null}

            </section>
          </div>
        )}
      </div>
    </main>
  );
}
