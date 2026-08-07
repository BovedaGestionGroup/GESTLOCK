type UserRecord = {
  id: string;
  email: string;
  passwordHash: string;
  role: string;
};

type RefreshTokenRecord = {
  token: string;
  userId: string;
  expiresAt: Date;
  revoked: boolean;
};

type AuditLogRecord = {
  id: string;
  userId?: string;
  action: string;
  details?: string;
  createdAt: Date;
};

type VaultEntryRecord = {
  id: string;
  userId: string;
  name: string;
  url: string;
  username: string;
  password: string;
  notes?: string;
  createdAt: string;
};

const users = new Map<string, UserRecord>();
const refreshTokens = new Map<string, RefreshTokenRecord>();
const auditLogs: AuditLogRecord[] = [];
const vaultEntries: VaultEntryRecord[] = [];

export const inMemoryStore = {
  async getUserByEmail(email: string) {
    return Array.from(users.values()).find((user) => user.email === email);
  },
  async createUser(user: UserRecord) {
    users.set(user.id, user);
    return user;
  },
  async getUserById(id: string) {
    return users.get(id);
  },
  async createRefreshToken(tokenRecord: RefreshTokenRecord) {
    refreshTokens.set(tokenRecord.token, tokenRecord);
    return tokenRecord;
  },
  async findRefreshToken(token: string) {
    return refreshTokens.get(token);
  },
  async updateRefreshToken(token: string, updates: Partial<RefreshTokenRecord>) {
    const existing = refreshTokens.get(token);
    if (!existing) return null;
    const updated = { ...existing, ...updates };
    refreshTokens.set(token, updated);
    return updated;
  },
  async createAuditLog(log: AuditLogRecord) {
    auditLogs.push(log);
    return log;
  },
  async createVaultEntry(entry: VaultEntryRecord) {
    vaultEntries.push(entry);
    return entry;
  },
  async listVaultEntries(userId: string, search?: string) {
    const normalized = search?.trim().toLowerCase();
    return vaultEntries.filter((entry) => {
      if (entry.userId !== userId) return false;
      if (!normalized) return true;
      return [entry.name, entry.url, entry.username, entry.notes ?? ''].some((value) =>
        value.toLowerCase().includes(normalized),
      );
    });
  },
  async updateVaultEntry(id: string, updates: Partial<VaultEntryRecord>) {
    const index = vaultEntries.findIndex((entry) => entry.id === id);
    if (index === -1) return null;
    const updated = { ...vaultEntries[index], ...updates };
    vaultEntries[index] = updated;
    return updated;
  },
  async deleteVaultEntry(id: string) {
    const index = vaultEntries.findIndex((entry) => entry.id === id);
    if (index === -1) return null;
    const [removed] = vaultEntries.splice(index, 1);
    return removed;
  },
  async clear() {
    users.clear();
    refreshTokens.clear();
    auditLogs.length = 0;
    vaultEntries.length = 0;
  },
};
