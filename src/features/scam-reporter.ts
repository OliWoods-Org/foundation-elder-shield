/**
 * Scam Reporter
 *
 * Streamlines the process of reporting elder financial fraud to appropriate
 * agencies. Auto-generates reports for Adult Protective Services, FBI IC3,
 * FTC, and local law enforcement.
 *
 * @module scam-reporter
 * @license GPL-3.0
 * @author OliWoods Foundation
 */

import { z } from 'zod';

// ── Schemas ──────────────────────────────────────────────────────────────────

export const FraudReportSchema = z.object({
  id: z.string().uuid(),
  victimName: z.string(),
  victimAge: z.number().int().positive(),
  victimState: z.string(),
  reporterName: z.string(),
  reporterRelationship: z.string(),
  scamType: z.enum([
    'romance', 'government-impersonation', 'tech-support', 'grandparent',
    'investment', 'lottery-prize', 'charity', 'identity-theft',
    'home-repair', 'caregiver-exploitation', 'power-of-attorney-abuse', 'other',
  ]),
  description: z.string(),
  totalLoss: z.number().nonnegative(),
  paymentMethods: z.array(z.enum(['wire-transfer', 'gift-cards', 'cash', 'check', 'cryptocurrency', 'credit-card', 'debit-card', 'zelle-venmo', 'other'])),
  dateFirstContact: z.string().datetime(),
  dateLastContact: z.string().datetime(),
  suspectInfo: z.object({
    name: z.string().optional(),
    phone: z.string().optional(),
    email: z.string().optional(),
    website: z.string().optional(),
    socialMedia: z.string().optional(),
    bankAccount: z.string().optional(),
  }).optional(),
  evidenceCollected: z.array(z.enum(['phone-records', 'text-messages', 'emails', 'bank-statements', 'screenshots', 'recordings', 'receipts', 'gift-card-numbers'])),
  agencySubmissions: z.array(z.object({
    agency: z.string(),
    submissionDate: z.string().datetime().optional(),
    referenceNumber: z.string().optional(),
    status: z.enum(['pending', 'submitted', 'acknowledged', 'investigating', 'closed']),
    url: z.string().url().optional(),
  })),
  createdAt: z.string().datetime(),
  urgency: z.enum(['routine', 'urgent', 'emergency']),
});

export const AgencyInfoSchema = z.object({
  name: z.string(),
  jurisdiction: z.enum(['federal', 'state', 'local']),
  website: z.string().url(),
  phone: z.string(),
  reportingUrl: z.string().url().optional(),
  description: z.string(),
  handles: z.array(z.string()),
  averageResponseDays: z.number().int().positive().optional(),
});

export const RecoveryStepSchema = z.object({
  order: z.number().int().positive(),
  action: z.string(),
  agency: z.string().optional(),
  deadline: z.string().optional(),
  critical: z.boolean(),
  completed: z.boolean().optional(),
  notes: z.string().optional(),
});

// ── Types ────────────────────────────────────────────────────────────────────

export type FraudReport = z.infer<typeof FraudReportSchema>;
export type AgencyInfo = z.infer<typeof AgencyInfoSchema>;
export type RecoveryStep = z.infer<typeof RecoveryStepSchema>;

// ── Agency Database ──────────────────────────────────────────────────────────

const REPORTING_AGENCIES: AgencyInfo[] = [
  {
    name: 'FBI Internet Crime Complaint Center (IC3)',
    jurisdiction: 'federal',
    website: 'https://www.ic3.gov',
    phone: '1-800-CALL-FBI',
    reportingUrl: 'https://www.ic3.gov/Home/FileComplaint',
    description: 'Primary federal agency for internet-enabled financial crimes',
    handles: ['romance', 'investment', 'tech-support', 'lottery-prize', 'identity-theft'],
  },
  {
    name: 'Federal Trade Commission (FTC)',
    jurisdiction: 'federal',
    website: 'https://reportfraud.ftc.gov',
    phone: '1-877-FTC-HELP',
    reportingUrl: 'https://reportfraud.ftc.gov',
    description: 'Consumer protection agency tracking fraud patterns',
    handles: ['romance', 'government-impersonation', 'tech-support', 'lottery-prize', 'charity', 'identity-theft'],
  },
  {
    name: 'Adult Protective Services (APS)',
    jurisdiction: 'state',
    website: 'https://eldercare.acl.gov',
    phone: '1-800-677-1116',
    description: 'State-level agency for investigating elder abuse and exploitation',
    handles: ['caregiver-exploitation', 'power-of-attorney-abuse', 'home-repair'],
    averageResponseDays: 3,
  },
  {
    name: 'Consumer Financial Protection Bureau (CFPB)',
    jurisdiction: 'federal',
    website: 'https://www.consumerfinance.gov',
    phone: '1-855-411-CFPB',
    reportingUrl: 'https://www.consumerfinance.gov/complaint/',
    description: 'Financial product and service complaints',
    handles: ['investment', 'identity-theft'],
  },
  {
    name: 'Social Security Administration OIG',
    jurisdiction: 'federal',
    website: 'https://oig.ssa.gov',
    phone: '1-800-269-0271',
    reportingUrl: 'https://oig.ssa.gov/report/',
    description: 'SSA impersonation and Social Security fraud',
    handles: ['government-impersonation'],
  },
];

// ── Functions ────────────────────────────────────────────────────────────────

/**
 * Determine which agencies should receive a fraud report based on scam type,
 * jurisdiction, and loss amount.
 */
export function determineReportingAgencies(
  scamType: FraudReport['scamType'],
  state: string,
  totalLoss: number,
): AgencyInfo[] {
  const agencies: AgencyInfo[] = [];

  // Always include APS for elder victims
  const aps = REPORTING_AGENCIES.find(a => a.name.includes('Adult Protective'));
  if (aps) agencies.push(aps);

  // Match by scam type
  for (const agency of REPORTING_AGENCIES) {
    if (agency.handles.includes(scamType) && !agencies.includes(agency)) {
      agencies.push(agency);
    }
  }

  // FTC for all types
  const ftc = REPORTING_AGENCIES.find(a => a.name.includes('FTC'));
  if (ftc && !agencies.includes(ftc)) agencies.push(ftc);

  // FBI IC3 for losses over $1000
  if (totalLoss > 1000) {
    const ic3 = REPORTING_AGENCIES.find(a => a.name.includes('IC3'));
    if (ic3 && !agencies.includes(ic3)) agencies.push(ic3);
  }

  return agencies;
}

/**
 * Generate a step-by-step recovery plan after fraud has been identified.
 */
export function generateRecoveryPlan(
  report: FraudReport,
): RecoveryStep[] {
  const steps: RecoveryStep[] = [];
  let order = 1;

  // Immediate actions
  if (report.urgency === 'emergency' || report.totalLoss > 10000) {
    steps.push({
      order: order++,
      action: 'Call your bank/financial institution immediately to freeze accounts and attempt to reverse transactions',
      agency: 'Your bank',
      deadline: 'IMMEDIATELY',
      critical: true,
    });
  }

  // Wire transfer recovery
  if (report.paymentMethods.includes('wire-transfer')) {
    steps.push({
      order: order++,
      action: 'Contact your bank to initiate a wire recall. Request they contact the receiving bank. Time is critical — wire recalls are most successful within 24-72 hours.',
      agency: 'Your bank',
      deadline: 'Within 24 hours',
      critical: true,
    });
  }

  // Credit card chargeback
  if (report.paymentMethods.includes('credit-card')) {
    steps.push({
      order: order++,
      action: 'Dispute the charges with your credit card company. Federal law limits liability to $50 for unauthorized charges.',
      agency: 'Credit card issuer',
      deadline: 'Within 60 days of statement',
      critical: true,
    });
  }

  // Gift card recovery
  if (report.paymentMethods.includes('gift-cards')) {
    steps.push({
      order: order++,
      action: 'Contact each gift card company with the card numbers. Some companies may be able to freeze remaining balances.',
      deadline: 'As soon as possible',
      critical: true,
    });
  }

  // Cryptocurrency
  if (report.paymentMethods.includes('cryptocurrency')) {
    steps.push({
      order: order++,
      action: 'Report to the cryptocurrency exchange. File with FBI IC3 including wallet addresses. Recovery is difficult but not impossible.',
      agency: 'FBI IC3',
      critical: true,
    });
  }

  // Identity theft protection
  if (report.scamType === 'identity-theft' || report.evidenceCollected.includes('bank-statements')) {
    steps.push({
      order: order++,
      action: 'Place a fraud alert on credit reports at all three bureaus (Equifax, Experian, TransUnion). Consider a credit freeze.',
      deadline: 'Within 24 hours',
      critical: true,
    });
    steps.push({
      order: order++,
      action: 'File an Identity Theft Report at IdentityTheft.gov',
      agency: 'FTC',
      deadline: 'Within 48 hours',
      critical: true,
    });
  }

  // Agency reporting
  const agencies = determineReportingAgencies(report.scamType, report.victimState, report.totalLoss);
  for (const agency of agencies) {
    steps.push({
      order: order++,
      action: `File a report with ${agency.name}${agency.reportingUrl ? ` at ${agency.reportingUrl}` : ` — call ${agency.phone}`}`,
      agency: agency.name,
      deadline: 'Within 1 week',
      critical: agency.jurisdiction === 'state',
    });
  }

  // Follow-up
  steps.push({
    order: order++,
    action: 'Keep copies of all reports, reference numbers, and correspondence. Create a timeline of events.',
    critical: false,
  });
  steps.push({
    order: order++,
    action: 'Change passwords on all financial accounts and email. Enable two-factor authentication.',
    deadline: 'Within 48 hours',
    critical: true,
  });

  return steps;
}

/**
 * Estimate potential recovery based on payment method and reporting speed.
 */
export function estimateRecovery(
  paymentMethods: FraudReport['paymentMethods'],
  totalLoss: number,
  daysSinceLastTransaction: number,
): {
  estimatedRecovery: number;
  recoveryProbability: string;
  byMethod: Array<{ method: string; likelihood: string; notes: string }>;
} {
  const byMethod: Array<{ method: string; likelihood: string; notes: string }> = [];
  let totalRecoverable = 0;

  for (const method of paymentMethods) {
    let likelihood = 'Low';
    let notes = '';
    let recoverablePercent = 0;

    switch (method) {
      case 'credit-card':
        likelihood = daysSinceLastTransaction < 60 ? 'High' : 'Moderate';
        notes = 'Federal law limits liability to $50. Dispute within 60 days.';
        recoverablePercent = daysSinceLastTransaction < 60 ? 0.9 : 0.4;
        break;
      case 'debit-card':
        likelihood = daysSinceLastTransaction < 2 ? 'High' : daysSinceLastTransaction < 60 ? 'Moderate' : 'Low';
        notes = 'Report within 2 days: $50 max loss. Within 60 days: $500 max. After 60 days: unlimited loss.';
        recoverablePercent = daysSinceLastTransaction < 2 ? 0.8 : daysSinceLastTransaction < 60 ? 0.5 : 0.1;
        break;
      case 'wire-transfer':
        likelihood = daysSinceLastTransaction < 1 ? 'Moderate' : 'Low';
        notes = 'Wire recalls must be initiated within 24 hours for best chance. Success rate drops dramatically after.';
        recoverablePercent = daysSinceLastTransaction < 1 ? 0.3 : 0.05;
        break;
      case 'gift-cards':
        likelihood = 'Very Low';
        notes = 'Gift cards are nearly untraceable once redeemed. Some issuers may freeze unredeemed balances.';
        recoverablePercent = 0.05;
        break;
      case 'cryptocurrency':
        likelihood = 'Very Low';
        notes = 'Cryptocurrency transactions are generally irreversible. Law enforcement may trace funds in some cases.';
        recoverablePercent = 0.03;
        break;
      case 'cash':
        likelihood = 'Very Low';
        notes = 'Cash is extremely difficult to recover once handed over.';
        recoverablePercent = 0.01;
        break;
      default:
        likelihood = 'Unknown';
        notes = 'Contact your financial institution for recovery options.';
        recoverablePercent = 0.2;
    }

    byMethod.push({ method, likelihood, notes });
    totalRecoverable += recoverablePercent;
  }

  const avgRecovery = paymentMethods.length > 0 ? totalRecoverable / paymentMethods.length : 0;
  const estimatedRecovery = Math.round(totalLoss * avgRecovery);

  return {
    estimatedRecovery,
    recoveryProbability: avgRecovery > 0.6 ? 'Good' : avgRecovery > 0.3 ? 'Moderate' : 'Low',
    byMethod,
  };
}
