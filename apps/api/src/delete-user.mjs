import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
async function main() {
  const result = await prisma.user.deleteMany({
    where: { email: 'anexos@gestiongroup.es' },
  });
  console.log(`Deleted ${result.count} user(s)`);
}
main().catch(console.error).finally(() => prisma.$disconnect());
