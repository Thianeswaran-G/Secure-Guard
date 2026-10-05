import { Body, Controller, Get, Put } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
@Controller('settings')
export class SettingsController {
  constructor(private readonly prisma: PrismaService) {}
  @Get() async get() { const rows = await this.prisma.setting.findMany(); return Object.fromEntries(rows.map(row => [row.key, row.value])); }
  @Put() async replace(@Body() body: Record<string, unknown>) {
    await this.prisma.$transaction(Object.entries(body).map(([key, value]) => this.prisma.setting.upsert({ where: { key }, update: { value: value as object }, create: { key, value: value as object } })));
    return this.get();
  }
}
