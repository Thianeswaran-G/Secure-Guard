import { Module } from '@nestjs/common';
import { WhitelistController } from './whitelist.controller';
@Module({ controllers: [WhitelistController] })
export class WhitelistModule {}
