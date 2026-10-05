import { Body, Controller, Delete, Get, Param, Post } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
@Controller('whitelist')
export class WhitelistController {
  constructor(private readonly prisma: PrismaService) {}
  @Get() list() { return this.prisma.whitelistEntry.findMany({ orderBy: { hostname: 'asc' } }); }
  @Post() add(@Body() body: { hostname: string }) { const hostname = body.hostname.trim().toLowerCase(); return this.prisma.whitelistEntry.upsert({ where: { hostname }, update: {}, create: { hostname } }); }
  @Delete(':hostname') remove(@Param('hostname') hostname: string) { return this.prisma.whitelistEntry.delete({ where: { hostname } }); }
}
