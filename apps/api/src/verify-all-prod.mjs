import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function verifyAll() {
  const users = await prisma.user.updateMany({
    data: { isVerified: true, verificationCode: null }
  });
  console.log(`Verified ${users.count} users.`);
}

verifyAll()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
