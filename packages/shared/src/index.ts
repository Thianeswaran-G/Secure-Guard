export type Severity =
  | 'LOW'
  | 'MEDIUM'
  | 'HIGH'
  | 'CRITICAL';

export type ScanType =
  | 'FORM'
  | 'FILE'
  | 'URL'
  | 'REQUEST'
  | 'HEADER';

export type FindingType =
  | 'PASSWORD'
  | 'CREDIT_CARD'
  | 'CVV'
  | 'OTP'
  | 'TOKEN'
  | 'SECRET'
  | 'API_KEY'
  | 'AADHAAR'
  | 'SSN'
  | 'SENSITIVE_FILE';

export interface ScanEvent {
  url: string;
  hostname: string;
  scanType: ScanType;
  riskScore: number;
  severity: Severity;
  findings: FindingType[];
  timestamp: string;
}

export interface ScanResponse {
  id: string;
  createdAt: string;
  scan: ScanEvent;
}

export interface ApiError {
  statusCode: number;
  message: string | string[];
  error?: string;
}

export interface ExtensionSettings {
  realTimeScanning: boolean;
  autoBlock: boolean;
  notifications: boolean;
  darkWebScanning: boolean;
  alertLevel: Severity;
}

export interface ExtensionStats {
  sitesScanned: number;
  alertsGenerated: number;
  blockedRequests: number;
}