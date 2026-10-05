import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { CreateScanDto } from './dto/create-scan.dto';
import { ScansService } from './scans.service';
@Controller('scans')
export class ScansController { constructor(private readonly service: ScansService) {} @Post() create(@Body() dto: CreateScanDto) { return this.service.create(dto); } @Get('recent') recent(@Query('limit') limit?: string) { return this.service.recent(limit ? Number(limit) : 50); } @Get('summary') summary() { return this.service.summary(); } }
