import { IsBoolean, IsOptional, IsString, IsUrl, IsEnum } from 'class-validator';
import type { Severity } from '@secureguard/shared';
export class CreateAlertDto {
  @IsOptional() @IsString() scanId?: string;
  @IsString() type!: string;
  @IsEnum(['LOW','MEDIUM','HIGH','CRITICAL']) severity!: Severity;
  @IsString() title!: string;
  @IsString() message!: string;
  @IsUrl({ require_tld: false }) url!: string;
  @IsString() hostname!: string;
  @IsOptional() @IsBoolean() blocked?: boolean;
}
