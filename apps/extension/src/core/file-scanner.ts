import type {
  FindingType,
  Severity,
} from '@secureguard/shared';

export interface FileScanResult {
  fileName: string;
  extension: string;
  size: number;
  findings: FindingType[];
  descriptions: string[];
  score: number;
  severity: Severity;
}

const SENSITIVE_EXTENSIONS = [
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'csv',
  'zip',
  'rar',
  'sql',
  'bak',
  'json',
  'pem',
  'key',
];

const SENSITIVE_KEYWORDS = [
  'resume',
  'aadhaar',
  'aadhar',
  'passport',
  'salary',
  'bank',
  'statement',
  'invoice',
  'confidential',
  'employee',
  'customer',
  'database',
  'backup',
  'secret',
  'private',
];

const EXECUTABLE_EXTENSIONS = [
  'exe',
  'bat',
  'cmd',
  'sh',
  'msi',
];

function getSeverity(
  score: number,
): Severity {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';

  return 'LOW';
}

export function getExtension(
  fileName: string,
): string {
  const lastDot =
    fileName.lastIndexOf('.');

  if (
    lastDot === -1 ||
    lastDot === fileName.length - 1
  ) {
    return '';
  }

  return fileName
    .slice(lastDot + 1)
    .toLowerCase();
}

export function scanFile(
  file: File,
): FileScanResult {
  const extension =
    getExtension(file.name);

  const findings: FindingType[] = [];
  const descriptions: string[] = [];

  let score = 0;

  if (
    SENSITIVE_EXTENSIONS.includes(
      extension,
    )
  ) {
    findings.push('SENSITIVE_FILE');

    descriptions.push(
      'Sensitive file type',
    );

    score += 20;
  }

  const lowerName =
    file.name.toLowerCase();

  for (
    const keyword of
    SENSITIVE_KEYWORDS
  ) {
    if (
      lowerName.includes(keyword)
    ) {
      if (
        !findings.includes(
          'SENSITIVE_FILE',
        )
      ) {
        findings.push(
          'SENSITIVE_FILE',
        );
      }

      descriptions.push(
        `Sensitive filename: ${keyword}`,
      );

      score += 15;
    }
  }

  if (
    file.size >
    10 * 1024 * 1024
  ) {
    descriptions.push(
      'Large file',
    );

    score += 10;
  }

  if (
    EXECUTABLE_EXTENSIONS.includes(
      extension,
    )
  ) {
    findings.push(
      'SENSITIVE_FILE',
    );

    descriptions.push(
      'Executable file',
    );

    score += 40;
  }

  return {
    fileName: file.name,
    extension,
    size: file.size,
    findings: [
      ...new Set(findings),
    ],
    descriptions,
    score: Math.min(100, score),
    severity: getSeverity(score),
  };
}