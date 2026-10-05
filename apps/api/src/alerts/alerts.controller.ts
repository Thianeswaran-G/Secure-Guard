import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { AlertsService } from './alerts.service';
import { CreateAlertDto } from './dto/create-alert.dto';
@Controller('alerts')
export class AlertsController {
  constructor(private readonly service: AlertsService) {}
  @Post() create(@Body() dto: CreateAlertDto) { return this.service.create(dto); }
  @Get('recent') recent(@Query('limit') limit?: string) { return this.service.recent(limit ? Number(limit) : 50); }
}
