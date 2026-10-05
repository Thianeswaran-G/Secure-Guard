import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateAlertDto } from './dto/create-alert.dto';
@Injectable()
export class AlertsService {
  constructor(private readonly prisma: PrismaService) {}
  create(dto: CreateAlertDto) { return this.prisma.alert.create({ data: { ...dto, blocked: dto.blocked ?? false } }); }
  recent(limit = 50) { return this.prisma.alert.findMany({ orderBy: { createdAt: 'desc' }, take: Math.min(Math.max(limit, 1), 200) }); }
}
