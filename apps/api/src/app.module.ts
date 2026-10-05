import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { PrismaModule } from "./prisma/prisma.module";
import { ScansModule } from "./scans/scans.module";
import { AlertsModule } from "./alerts/alerts.module";
import { SettingsModule } from "./settings/settings.module";
import { WhitelistModule } from "./whitelist/whitelist.module";
import { HealthController } from "./health/health.controller";
@Module({
  imports: [
    PrismaModule,
    ScansModule,
    AlertsModule,
    SettingsModule,
    WhitelistModule,
    ConfigModule.forRoot({isGlobal: true,}),
  ],
  controllers: [HealthController],
})
export class AppModule {}
