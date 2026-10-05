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

interface DetectionRule {
  type: FindingType;
  fieldKeywords: string[];
  pattern?: RegExp;
}

function passesLuhn(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, '');
  let sum = 0;
  let doubleDigit = false;

  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);

    if (doubleDigit) {
      digit *= 2;

      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    doubleDigit = !doubleDigit;
  }

  return sum % 10 === 0;
}

function hasCardFieldContext(
  text: string,
  valueIndex: number,
): boolean {
  const prefix = text
    .slice(Math.max(0, valueIndex - 100), valueIndex)
    .replace(/["'\s]+$/, '');
  const field = prefix.match(
    /(?:^|[,{&])\s*["']?([\w.-]+)["']?\s*[:=]\s*$/,
  )?.[1];

  return Boolean(
    field &&
    /card|credit/i.test(field),
  );
}

function isStandaloneCardNumber(text: string): boolean {
  return /^\s*[\d -]{13,23}\s*$/.test(text) &&
    passesLuhn(text);
}

function matchesPattern(
  rule: DetectionRule,
  text: string,
): boolean {
  if (!rule.pattern) {
    return false;
  }

  if (rule.type !== 'CREDIT_CARD') {
    return rule.pattern.test(text);
  }

  const candidates = new RegExp(
    rule.pattern.source,
    'g',
  );

  for (const match of text.matchAll(candidates)) {
    if (
      passesLuhn(match[0]) &&
      (
        hasCardFieldContext(text, match.index ?? 0) ||
        isStandaloneCardNumber(text)
      )
    ) {
      return true;
    }
  }

  return false;
}

const RULES: DetectionRule[] = [
  {
    type: 'PASSWORD',
    fieldKeywords: [
      'password',
      'passwd',
      'pwd',
    ],
  },
  {
    type: 'CREDIT_CARD',
    fieldKeywords: [
      'card',
      'credit',
      'creditcard',
      'cardnumber',
      'card_number',
    ],
    pattern:
      /\b(?:\d[ -]*?){13,19}\b/,
  },
  {
    type: 'CVV',
    fieldKeywords: [
      'cvv',
      'cvc',
      'securitycode',
      'security_code',
    ],
  },
  {
    type: 'OTP',
    fieldKeywords: [
      'otp',
      'one-time',
      'verificationcode',
      'verification_code',
      'passcode',
    ],
  },
  {
    type: 'TOKEN',
    fieldKeywords: [
      'token',
      'access_token',
      'accesstoken',
      'refresh_token',
      'refreshtoken',
      'bearer',
    ],
  },
  {
    type: 'SECRET',
    fieldKeywords: [
      'secret',
      'privatekey',
      'private_key',
    ],
  },
  {
    type: 'API_KEY',
    fieldKeywords: [
      'api',
      'apikey',
      'api_key',
      'x-api-key',
    ],
  },
  {
    type: 'AADHAAR',
    fieldKeywords: [
      'aadhaar',
      'aadhar',
    ],
    pattern:
      /\b\d{4}\s?\d{4}\s?\d{4}\b/,
  },
  {
    type: 'SSN',
    fieldKeywords: [
      'ssn',
      'socialsecurity',
      'social_security',
    ],
    pattern:
      /\b\d{3}-\d{2}-\d{4}\b/,
  },
];

function normalize(
  value: unknown,
): string {
  return String(value ?? '')
    .trim()
    .toLowerCase();
}

export function detectSensitiveField(
  name: string,
  value: unknown = '',
  inputType = '',
  id = '',
): FindingType | null {
  const fieldName =
    normalize(name);

  const fieldId =
    normalize(id);

  const type =
    normalize(inputType);

  const fieldValue =
    String(value ?? '');

  for (const rule of RULES) {
    const matchesKeyword =
      rule.fieldKeywords.some(
        (keyword) =>
          fieldName.includes(keyword) ||
          fieldId.includes(keyword) ||
          type.includes(keyword),
      );

    if (matchesKeyword) {
      return rule.type;
    }

    if (matchesPattern(rule, fieldValue)) {
      return rule.type;
    }
  }

  return null;
}

export interface TextDetectionResult {
  findings: FindingType[];
  score: number;
}

export function detectSensitiveText(
  text: string,
): TextDetectionResult {
  const findings: FindingType[] = [];

  for (const rule of RULES) {
    if (matchesPattern(rule, text)) {
      findings.push(rule.type);
    }

    const fieldKeywords =
      rule.type === 'CREDIT_CARD'
        ? rule.fieldKeywords.filter(
          (keyword) =>
            keyword !== 'card' &&
            keyword !== 'credit',
        )
        : rule.fieldKeywords;

    /*
     * These rules are intentionally checked against
     * the text as well because request bodies often
     * contain key=value pairs instead of form fields.
     */
    if (
      fieldKeywords.some(
        (keyword) =>
          new RegExp(
            `(?:^|[\\s&=:"'{}])${escapeRegex(
              keyword,
            )}(?:$|[\\s&=:"'{}])`,
            'i',
          ).test(text),
      )
    ) {
      findings.push(rule.type);
    }
  }

  const uniqueFindings = [
    ...new Set(findings),
  ];

  return {
    findings: uniqueFindings,
    score: calculateDetectionScore(
      uniqueFindings,
    ),
  };
}

function escapeRegex(
  value: string,
): string {
  return value.replace(
    /[.*+?^${}()|[\]\\]/g,
    '\\$&',
  );
}

export function calculateDetectionScore(
  findings: FindingType[],
): number {
  const weights: Record<
    FindingType,
    number
  > = {
    PASSWORD: 25,
    CREDIT_CARD: 35,
    CVV: 35,
    OTP: 30,
    TOKEN: 35,
    SECRET: 35,
    API_KEY: 40,
    AADHAAR: 35,
    SSN: 40,
    SENSITIVE_FILE: 20,
  };

  return Math.min(
    100,
    [...new Set(findings)].reduce(
      (total, finding) =>
        total + weights[finding],
      0,
    ),
  );
}