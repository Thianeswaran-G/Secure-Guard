import { IsArray, IsDateString, IsEnum, IsInt, IsString, IsUrl, Max, Min } from 'class-validator';
import type { FindingType, ScanType, Severity } from '@secureguard/shared';
export class CreateScanDto {
  @IsUrl({ require_tld: false }) url!: string;
  @IsString() hostname!: string;
  @IsEnum(['FORM','FILE','URL','REQUEST','HEADER']) scanType!: ScanType;
  @IsInt() @Min(0) @Max(100) riskScore!: number;
  @IsEnum(['LOW','MEDIUM','HIGH','CRITICAL']) severity!: Severity;
  @IsArray() findings!: FindingType[];
  @IsDateString() timestamp!: string;
}
