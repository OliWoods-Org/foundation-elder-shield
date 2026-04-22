/**
 * Transaction Monitor
 *
 * Monitors financial transactions for patterns indicative of elder fraud,
 * including sudden large withdrawals, new payees, gift card purchases,
 * wire transfers, and unusual account activity.
 *
 * @module transaction-monitor
 * @license GPL-3.0
 * @author OliWoods Foundation
 */

import { z } from 'zod';

// ── Schemas ──────────────────────────────────────────────────────────────────

export const TransactionSchema = z.object({
  id: z.string().uuid(),
  accountId: z.string(),
  timestamp: z.string().datetime(),
  type: z.enum(['withdrawal', 'deposit', 'transfer', 'purchase', 'wire', 'check', 'ach', 'atm', 'online']),
  amount: z.number(),
  currency: z.string().default('USD'),
  merchant: z.string().optional(),
  merchantCategory: z.string().optional(),
  payee: z.string().optional(),
  description: z.string().optional(),
  location: z.object({ city: z.string(), state: z.string(), country: z.string() }).optional(),
  isRecurring: z.boolean().default(false),
  channel: z.enum(['in-person', 'online', 'phone', 'atm', 'mobile']),
});

export const FraudAlertSchema = z.object({
  id: z.string().uuid(),
  transactionId: z.string().uuid(),
  accountId: z.string(),
  alertType: z.enum([
    'large-withdrawal', 'new-payee-large', 'gift-card-purchase', 'wire-transfer-unusual',
    'rapid-succession', 'unusual-location', 'account-drain', 'romance-scam-pattern',
    'government-impersonation', 'tech-support-scam', 'investment-scam', 'grandparent-scam',
  ]),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  riskScore: z.number().min(0).max(100),
  description: z.string(),
  recommendedActions: z.array(z.string()),
  guardianNotified: z.boolean().default(false),
  createdAt: z.string().datetime(),
});

export const AccountProfileSchema = z.object({
  id: z.string(),
  holderName: z.string(),
  holderAge: z.number().int().positive(),
  averageMonthlyBalance: z.number().nonnegative(),
  averageMonthlySpend: z.number().nonnegative(),
  typicalPayees: z.array(z.string()),
  typicalLocations: z.array(z.string()),
  guardianContacts: z.array(z.object({
    name: z.string(),
    relationship: z.string(),
    phone: z.string(),
    email: z.string().email(),
    notifyThreshold: z.enum(['all', 'medium', 'high', 'critical']),
  })),
  hasOnlineBanking: z.boolean(),
  typicalTransactionRange: z.object({ min: z.number(), max: z.number() }),
});

export const ScamPatternSchema = z.object({
  name: z.string(),
  indicators: z.array(z.string()),
  typicalLoss: z.string(),
  ageGroup: z.string(),
  reportTo: z.array(z.string()),
});

// ── Types ────────────────────────────────────────────────────────────────────

export type Transaction = z.infer<typeof TransactionSchema>;
export type FraudAlert = z.infer<typeof FraudAlertSchema>;
export type AccountProfile = z.infer<typeof AccountProfileSchema>;
export type ScamPattern = z.infer<typeof ScamPatternSchema>;

// ── Known Scam Patterns ─────────────────────────────────────────────────────

const SCAM_PATTERNS: ScamPattern[] = [
  {
    name: 'Gift Card Scam',
    indicators: ['Gift card purchases over $200', 'Multiple gift cards in one day', 'Gift cards from unusual retailers'],
    typicalLoss: '$1,000 - $10,000',
    ageGroup: '60+',
    reportTo: ['FTC (ReportFraud.ftc.gov)', 'Local police', 'Adult Protective Services'],
  },
  {
    name: 'Government Impersonation',
    indicators: ['Wire transfer after phone call', 'Payment to unknown entity claiming government authority', 'Urgency/threat language'],
    typicalLoss: '$5,000 - $50,000',
    ageGroup: '60+',
    reportTo: ['FTC', 'FBI IC3', 'SSA OIG (if SSA impersonation)'],
  },
  {
    name: 'Romance Scam',
    indicators: ['Escalating transfers to same individual', 'Wire transfers to overseas accounts', 'Pattern over weeks/months'],
    typicalLoss: '$10,000 - $100,000+',
    ageGroup: '55+',
    reportTo: ['FTC', 'FBI IC3', 'Dating platform'],
  },
  {
    name: 'Tech Support Scam',
    indicators: ['Payment after unsolicited call', 'Remote access software purchase', 'Gift card payment for "services"'],
    typicalLoss: '$500 - $5,000',
    ageGroup: '60+',
    reportTo: ['FTC', 'FBI IC3', 'State AG'],
  },
];

// ── Constants ────────────────────────────────────────────────────────────────

const GIFT_CARD_MERCHANTS = ['amazon', 'apple', 'google play', 'itunes', 'steam', 'target gift', 'walmart gift', 'best buy gift', 'ebay gift'];

// ── Functions ────────────────────────────────────────────────────────────────

/**
 * Analyze a transaction against the account holder's profile and known
 * scam patterns. Returns fraud alerts if suspicious activity is detected.
 */
export function analyzeTransaction(
  transaction: Transaction,
  profile: AccountProfile,
  recentTransactions: Transaction[],
): FraudAlert[] {
  const alerts: FraudAlert[] = [];
  const now = new Date().toISOString();

  // Check 1: Large withdrawal relative to profile
  if (transaction.amount > profile.typicalTransactionRange.max * 2 &&
      ['withdrawal', 'transfer', 'wire'].includes(transaction.type)) {
    const severity = transaction.amount > profile.averageMonthlyBalance * 0.25 ? 'critical' : 'high';
    alerts.push(createAlert(transaction, profile, 'large-withdrawal', severity,
      `Withdrawal of $${transaction.amount.toLocaleString()} is ${Math.round(transaction.amount / profile.typicalTransactionRange.max)}x the typical maximum`,
      now));
  }

  // Check 2: Gift card purchases (top scam vector)
  if (transaction.merchantCategory?.toLowerCase().includes('gift') ||
      GIFT_CARD_MERCHANTS.some(gc => (transaction.merchant || '').toLowerCase().includes(gc))) {
    if (transaction.amount > 200) {
      alerts.push(createAlert(transaction, profile, 'gift-card-purchase', 'high',
        `Gift card purchase of $${transaction.amount.toLocaleString()} detected. Gift cards are the #1 payment method demanded by scammers.`,
        now));
    }
  }

  // Check 3: New payee with large amount
  if (transaction.payee && !profile.typicalPayees.includes(transaction.payee) && transaction.amount > 1000) {
    alerts.push(createAlert(transaction, profile, 'new-payee-large', 'medium',
      `$${transaction.amount.toLocaleString()} to new payee "${transaction.payee}" not in typical payee list`,
      now));
  }

  // Check 4: Unusual wire transfer
  if (transaction.type === 'wire' && transaction.amount > 500) {
    const severity = transaction.amount > 5000 ? 'critical' : 'high';
    alerts.push(createAlert(transaction, profile, 'wire-transfer-unusual', severity,
      `Wire transfer of $${transaction.amount.toLocaleString()} detected. Wire transfers are irreversible and commonly used in fraud.`,
      now));
  }

  // Check 5: Rapid succession (multiple transactions in short period)
  const last24h = recentTransactions.filter(t => {
    const diff = new Date(transaction.timestamp).getTime() - new Date(t.timestamp).getTime();
    return diff > 0 && diff < 24 * 60 * 60 * 1000;
  });
  const last24hTotal = last24h.reduce((s, t) => s + t.amount, 0) + transaction.amount;
  if (last24hTotal > profile.averageMonthlySpend * 0.5 && last24h.length >= 3) {
    alerts.push(createAlert(transaction, profile, 'rapid-succession', 'high',
      `$${last24hTotal.toLocaleString()} in ${last24h.length + 1} transactions in 24 hours (50%+ of typical monthly spend)`,
      now));
  }

  // Check 6: Account drain pattern
  const last7d = recentTransactions.filter(t => {
    const diff = new Date(transaction.timestamp).getTime() - new Date(t.timestamp).getTime();
    return diff > 0 && diff < 7 * 24 * 60 * 60 * 1000;
  });
  const last7dWithdrawals = last7d.filter(t => ['withdrawal', 'transfer', 'wire'].includes(t.type));
  const last7dTotal = last7dWithdrawals.reduce((s, t) => s + t.amount, 0) + transaction.amount;
  if (last7dTotal > profile.averageMonthlyBalance * 0.4) {
    alerts.push(createAlert(transaction, profile, 'account-drain', 'critical',
      `$${last7dTotal.toLocaleString()} withdrawn in 7 days — ${Math.round((last7dTotal / profile.averageMonthlyBalance) * 100)}% of average balance. Possible account drain.`,
      now));
  }

  return alerts;
}

/**
 * Match transaction patterns against known scam typologies.
 */
export function detectScamPattern(
  transactions: Transaction[],
  profile: AccountProfile,
): Array<{ pattern: ScamPattern; confidence: number; matchingTransactions: string[]; totalExposure: number }> {
  const matches: Array<{ pattern: ScamPattern; confidence: number; matchingTransactions: string[]; totalExposure: number }> = [];

  // Gift card scam detection
  const giftCardTxns = transactions.filter(t =>
    GIFT_CARD_MERCHANTS.some(gc => (t.merchant || '').toLowerCase().includes(gc)) ||
    t.merchantCategory?.toLowerCase().includes('gift'),
  );
  if (giftCardTxns.length >= 2) {
    const total = giftCardTxns.reduce((s, t) => s + t.amount, 0);
    matches.push({
      pattern: SCAM_PATTERNS[0],
      confidence: Math.min(95, 50 + giftCardTxns.length * 15),
      matchingTransactions: giftCardTxns.map(t => t.id),
      totalExposure: total,
    });
  }

  // Romance scam detection (escalating transfers to same payee)
  const payeeGroups = new Map<string, Transaction[]>();
  for (const t of transactions) {
    if (t.payee && ['transfer', 'wire'].includes(t.type)) {
      if (!payeeGroups.has(t.payee)) payeeGroups.set(t.payee, []);
      payeeGroups.get(t.payee)!.push(t);
    }
  }
  for (const [payee, txns] of payeeGroups) {
    if (txns.length >= 3 && !profile.typicalPayees.includes(payee)) {
      const total = txns.reduce((s, t) => s + t.amount, 0);
      const sorted = txns.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
      const isEscalating = sorted.every((t, i) => i === 0 || t.amount >= sorted[i - 1].amount * 0.8);
      if (isEscalating && total > 5000) {
        matches.push({
          pattern: SCAM_PATTERNS[2],
          confidence: Math.min(90, 40 + txns.length * 10 + (total > 10000 ? 20 : 0)),
          matchingTransactions: txns.map(t => t.id),
          totalExposure: total,
        });
      }
    }
  }

  return matches.sort((a, b) => b.confidence - a.confidence);
}

/**
 * Generate a guardian notification with plain-language explanation.
 */
export function generateGuardianAlert(
  alert: FraudAlert,
  profile: AccountProfile,
): Array<{ contactName: string; message: string; urgency: string }> {
  return profile.guardianContacts
    .filter(g => {
      const thresholds = { all: 0, medium: 1, high: 2, critical: 3 };
      const severities = { low: 0, medium: 1, high: 2, critical: 3 };
      return severities[alert.severity] >= thresholds[g.notifyThreshold];
    })
    .map(guardian => ({
      contactName: guardian.name,
      message: `Alert for ${profile.holderName}: ${alert.description}. Risk score: ${alert.riskScore}/100. Recommended action: ${alert.recommendedActions[0]}`,
      urgency: alert.severity === 'critical' ? 'CALL IMMEDIATELY' : alert.severity === 'high' ? 'URGENT' : 'For your awareness',
    }));
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function createAlert(
  txn: Transaction, profile: AccountProfile, type: FraudAlert['alertType'],
  severity: FraudAlert['severity'], description: string, now: string,
): FraudAlert {
  const actions: string[] = [];
  if (severity === 'critical') {
    actions.push('Contact account holder immediately to verify transaction');
    actions.push('Consider temporary account freeze pending verification');
    actions.push('File SAR (Suspicious Activity Report) if confirmed fraud');
  }
  if (severity === 'high') {
    actions.push('Contact account holder to verify transaction');
    actions.push('Review recent account activity for additional suspicious patterns');
  }
  actions.push('Document incident for Adult Protective Services if exploitation confirmed');
  actions.push('Report to FBI IC3 (ic3.gov) and FTC (ReportFraud.ftc.gov)');

  return FraudAlertSchema.parse({
    id: crypto.randomUUID(),
    transactionId: txn.id,
    accountId: txn.accountId,
    alertType: type,
    severity,
    riskScore: severity === 'critical' ? 90 : severity === 'high' ? 70 : severity === 'medium' ? 50 : 30,
    description,
    recommendedActions: actions,
    guardianNotified: false,
    createdAt: now,
  });
}
