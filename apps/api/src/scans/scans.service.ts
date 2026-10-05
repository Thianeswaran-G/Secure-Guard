import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateScanDto } from './dto/create-scan.dto';
@Injectable()
export class ScansService {
  constructor(private readonly prisma: PrismaService) {}
  create(dto: CreateScanDto) { return this.prisma.scan.create({ data: { ...dto, findings: dto.findings, timestamp: new Date(dto.timestamp) } }); }
  recent(limit = 50) { return this.prisma.scan.findMany({ orderBy: { timestamp: 'desc' }, take: Math.min(Math.max(limit, 1), 200) }); }
  async summary() { const scans = await this.prisma.scan.findMany({ select: { riskScore: true, severity: true, scanType: true } }); const high = scans.filter(s => s.severity === 'HIGH' || s.severity === 'CRITICAL').length; const avg = scans.length ? Math.round(scans.reduce((sum, s) => sum + s.riskScore, 0) / scans.length) : 0; return { total: scans.length, highRisk: high, averageRisk: avg, byType: Object.fromEntries([...new Set(scans.map(s => s.scanType))].map(type => [type, scans.filter(s => s.scanType === type).length])) }; }
}
