import { PrismaClient } from '@prisma/client';

const prismaClient = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL ?? 'postgresql://gestor_user:gestor_password@localhost:5432/gestor_db?schema=public',
    },
  },
  log: process.env.NODE_ENV === 'test' ? [] : ['query'],
});

export const prisma = {
  user: {
    deleteMany: async () => prismaClient.user.deleteMany(),
    findUnique: async ({ where }: { where: { email?: string; id?: string } }) => {
      if (where.email) {
        return prismaClient.user.findUnique({ where: { email: where.email } });
      }
      if (where.id) {
        return prismaClient.user.findUnique({ where: { id: where.id } });
      }
      return null;
    },
    findMany: async ({ select, orderBy }: { select?: any; orderBy?: any }) =>
      prismaClient.user.findMany({ select, orderBy }),
    create: async ({ data }: { data: { email: string; passwordHash: string; role?: string; mfaEnabled?: boolean; mfaSecret?: string | null } }) =>
      prismaClient.user.create({ data }),
    update: async ({ where, data, select }: { where: { id: string }; data: any; select?: any }) => prismaClient.user.update({ where, data, select }),
  },
  refreshToken: {
    findUnique: async ({ where }: { where: { token?: string } }) => {
      if (!where.token) return null;
      return prismaClient.refreshToken.findUnique({ where: { token: where.token } });
    },
    deleteMany: async () => prismaClient.refreshToken.deleteMany(),
    create: async ({ data }: { data: { token: string; userId: string; expiresAt: Date; revoked?: boolean } }) =>
      prismaClient.refreshToken.create({ data }),
    updateMany: async ({ where, data }: { where: { token: string }; data: { revoked: boolean } }) =>
      prismaClient.refreshToken.updateMany({ where: { token: where.token }, data }),
  },
  vaultEntry: {
    create: async ({ data }: { data: any }) => prismaClient.vaultEntry.create({ data }),
    findUnique: async ({ where }: { where: { id: string } }) => prismaClient.vaultEntry.findUnique({ where }),
    findMany: async ({ where, search }: { where?: any; search?: string }) => {
      const resolvedWhere = where?.includeAll
        ? {}
        : where?.userId
          ? {
              OR: [
                { userId: where.userId },
                { shares: { some: { userId: where.userId } } },
              ],
            }
          : {};
      const items = await prismaClient.vaultEntry.findMany({ where: resolvedWhere });
      const normalized = search?.trim().toLowerCase();
      if (!normalized) return items;
      return items.filter((entry: any) => [entry.name, entry.url, entry.username, entry.notes ?? ''].some((value) => value.toLowerCase().includes(normalized)));
    },
    update: async ({ where, data }: { where: { id: string }; data: any }) => prismaClient.vaultEntry.update({ where, data }),
    delete: async ({ where }: { where: { id: string } }) => prismaClient.vaultEntry.delete({ where }),
  },
  vaultEntryShare: {
    findFirst: async ({ where }: { where: { entryId: string; userId: string } }) => prismaClient.vaultEntryShare.findFirst({ where }),
    create: async ({ data }: { data: { entryId: string; userId: string } }) => prismaClient.vaultEntryShare.create({ data }),
  },
  auditLog: {
    create: async ({ data }: { data: { userId?: string; action: string; details?: string; ipAddress?: string; userAgent?: string } }) =>
      prismaClient.auditLog.create({ data }),
    findMany: async ({ where, orderBy, take, include }: { where: any; orderBy?: any; take?: number; include?: any }) =>
      prismaClient.auditLog.findMany({ where, orderBy, take, include }),
    deleteMany: async () => prismaClient.auditLog.deleteMany(),
  },
};
