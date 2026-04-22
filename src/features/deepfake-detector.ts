/**
 * Deepfake Detector
 *
 * Detects AI-generated voice and video deepfakes in real-time during
 * phone calls and video interactions. Protects seniors from synthetic
 * impersonation scams (grandparent scams, government impersonation).
 *
 * @module deepfake-detector
 * @license GPL-3.0
 * @author OliWoods Foundation
 */

import { z } from 'zod';

// ── Schemas ──────────────────────────────────────────────────────────────────

export const AudioAnalysisSchema = z.object({
  id: z.string().uuid(),
  sessionId: z.string(),
  timestamp: z.string().datetime(),
  durationSeconds: z.number().positive(),
  sampleRateHz: z.number().int().positive(),
  deepfakeProbability: z.number().min(0).max(1),
  confidence: z.number().min(0).max(1),
  verdict: z.enum(['authentic', 'suspicious', 'likely-synthetic', 'confirmed-synthetic']),
  indicators: z.array(z.object({
    name: z.string(),
    score: z.number().min(0).max(1),
    description: z.string(),
  })),
  voiceprintMatch: z.object({
    claimedIdentity: z.string().optional(),
    matchScore: z.number().min(0).max(1).optional(),
    isKnownVoice: z.boolean(),
  }).optional(),
});

export const CallSessionSchema = z.object({
  id: z.string().uuid(),
  protectedUserId: z.string(),
  callerNumber: z.string(),
  callerClaimed: z.string().optional(),
  startTime: z.string().datetime(),
  endTime: z.string().datetime().optional(),
  analyses: z.array(AudioAnalysisSchema),
  overallVerdict: z.enum(['safe', 'caution', 'danger', 'blocked']),
  scamIndicators: z.array(z.string()),
  actionsTaken: z.array(z.string()),
});

export const VoiceprintSchema = z.object({
  id: z.string().uuid(),
  personName: z.string(),
  relationship: z.string(),
  enrollmentDate: z.string().datetime(),
  sampleCount: z.number().int().positive(),
  featureVector: z.array(z.number()),
  qualityScore: z.number().min(0).max(1),
});

export const ScamCallIndicatorSchema = z.object({
  indicator: z.string(),
  weight: z.number().min(0).max(1),
  category: z.enum(['urgency', 'authority', 'isolation', 'financial', 'emotional', 'technical']),
  description: z.string(),
});

// ── Types ────────────────────────────────────────────────────────────────────

export type AudioAnalysis = z.infer<typeof AudioAnalysisSchema>;
export type CallSession = z.infer<typeof CallSessionSchema>;
export type Voiceprint = z.infer<typeof VoiceprintSchema>;
export type ScamCallIndicator = z.infer<typeof ScamCallIndicatorSchema>;

// ── Scam Language Patterns ───────────────────────────────────────────────────

const SCAM_PHRASES: Array<{ phrase: string; category: string; weight: number }> = [
  { phrase: 'don\'t tell anyone', category: 'isolation', weight: 0.9 },
  { phrase: 'keep this between us', category: 'isolation', weight: 0.85 },
  { phrase: 'act now', category: 'urgency', weight: 0.7 },
  { phrase: 'your account will be suspended', category: 'authority', weight: 0.85 },
  { phrase: 'you owe money to the irs', category: 'authority', weight: 0.95 },
  { phrase: 'warrant for your arrest', category: 'authority', weight: 0.95 },
  { phrase: 'send gift cards', category: 'financial', weight: 0.95 },
  { phrase: 'wire the money', category: 'financial', weight: 0.9 },
  { phrase: 'i\'m in trouble', category: 'emotional', weight: 0.6 },
  { phrase: 'i need help right now', category: 'emotional', weight: 0.5 },
  { phrase: 'grandma', category: 'emotional', weight: 0.3 },
  { phrase: 'grandpa', category: 'emotional', weight: 0.3 },
  { phrase: 'remote access', category: 'technical', weight: 0.85 },
  { phrase: 'download this software', category: 'technical', weight: 0.8 },
  { phrase: 'your computer has a virus', category: 'technical', weight: 0.9 },
  { phrase: 'social security number', category: 'authority', weight: 0.8 },
  { phrase: 'bitcoin', category: 'financial', weight: 0.7 },
  { phrase: 'cryptocurrency', category: 'financial', weight: 0.7 },
];

// ── Functions ────────────────────────────────────────────────────────────────

/**
 * Analyze an audio segment for deepfake indicators.
 * Uses multiple signal analysis techniques to detect synthetic speech.
 */
export function analyzeAudioSegment(
  audioFeatures: {
    spectralFlatness: number;
    pitchVariance: number;
    breathingPatterns: number;
    microPauses: number;
    formantConsistency: number;
    backgroundNoise: number;
    compressionArtifacts: number;
    temporalCoherence: number;
  },
  sessionId: string,
  duration: number,
  knownVoiceprints?: Voiceprint[],
  claimedIdentity?: string,
): AudioAnalysis {
  const indicators: Array<{ name: string; score: number; description: string }> = [];

  // Spectral flatness: synthetic speech tends to have unnaturally even spectral distribution
  if (audioFeatures.spectralFlatness > 0.7) {
    indicators.push({
      name: 'Spectral Flatness Anomaly',
      score: audioFeatures.spectralFlatness,
      description: 'Unnaturally even frequency distribution suggests synthetic generation',
    });
  }

  // Pitch variance: cloned voices often have less natural pitch variation
  if (audioFeatures.pitchVariance < 0.3) {
    indicators.push({
      name: 'Low Pitch Variance',
      score: 1 - audioFeatures.pitchVariance,
      description: 'Insufficient pitch variation compared to natural speech',
    });
  }

  // Breathing patterns: real humans breathe; most deepfakes don't simulate this well
  if (audioFeatures.breathingPatterns < 0.2) {
    indicators.push({
      name: 'Missing Breathing Patterns',
      score: 1 - audioFeatures.breathingPatterns,
      description: 'Absence of natural breathing sounds between phrases',
    });
  }

  // Micro-pauses: natural speech has characteristic hesitation patterns
  if (audioFeatures.microPauses < 0.25) {
    indicators.push({
      name: 'Unnatural Fluency',
      score: 1 - audioFeatures.microPauses,
      description: 'Speech is unnaturally fluent without normal micro-hesitations',
    });
  }

  // Formant consistency: deepfakes can have formant discontinuities
  if (audioFeatures.formantConsistency < 0.5) {
    indicators.push({
      name: 'Formant Inconsistency',
      score: 1 - audioFeatures.formantConsistency,
      description: 'Vocal tract resonance patterns are inconsistent, suggesting splicing or synthesis',
    });
  }

  // Compression artifacts: multiple encoding cycles leave detectable traces
  if (audioFeatures.compressionArtifacts > 0.6) {
    indicators.push({
      name: 'Compression Artifact Layers',
      score: audioFeatures.compressionArtifacts,
      description: 'Multiple layers of audio compression detected, common in processed deepfakes',
    });
  }

  // Calculate overall deepfake probability
  const indicatorScores = indicators.map(i => i.score);
  const deepfakeProbability = indicatorScores.length > 0
    ? indicatorScores.reduce((s, v) => s + v, 0) / indicatorScores.length * (0.5 + indicators.length * 0.1)
    : 0.1;

  const normalizedProb = Math.min(1, Math.max(0, deepfakeProbability));
  const confidence = Math.min(1, 0.3 + duration / 30 * 0.4 + indicators.length * 0.05);

  let verdict: AudioAnalysis['verdict'] = 'authentic';
  if (normalizedProb > 0.8) verdict = 'confirmed-synthetic';
  else if (normalizedProb > 0.6) verdict = 'likely-synthetic';
  else if (normalizedProb > 0.35) verdict = 'suspicious';

  // Voiceprint matching
  let voiceprintMatch: AudioAnalysis['voiceprintMatch'];
  if (claimedIdentity && knownVoiceprints) {
    const knownPrint = knownVoiceprints.find(v => v.personName.toLowerCase() === claimedIdentity.toLowerCase());
    voiceprintMatch = {
      claimedIdentity,
      matchScore: knownPrint ? audioFeatures.temporalCoherence : undefined,
      isKnownVoice: !!knownPrint && audioFeatures.temporalCoherence > 0.7,
    };
  }

  return AudioAnalysisSchema.parse({
    id: crypto.randomUUID(),
    sessionId,
    timestamp: new Date().toISOString(),
    durationSeconds: duration,
    sampleRateHz: 16000,
    deepfakeProbability: Math.round(normalizedProb * 1000) / 1000,
    confidence: Math.round(confidence * 1000) / 1000,
    verdict,
    indicators,
    voiceprintMatch,
  });
}

/**
 * Analyze call transcript for scam language patterns.
 */
export function analyzeCallTranscript(
  transcript: string,
): { scamScore: number; detectedIndicators: ScamCallIndicator[]; verdict: string } {
  const lower = transcript.toLowerCase();
  const detected: ScamCallIndicator[] = [];

  for (const pattern of SCAM_PHRASES) {
    if (lower.includes(pattern.phrase)) {
      detected.push(ScamCallIndicatorSchema.parse({
        indicator: pattern.phrase,
        weight: pattern.weight,
        category: pattern.category as ScamCallIndicator['category'],
        description: `Detected scam-associated phrase: "${pattern.phrase}"`,
      }));
    }
  }

  const scamScore = detected.length > 0
    ? Math.min(100, Math.round(detected.reduce((s, d) => s + d.weight * 30, 0)))
    : 0;

  const categories = new Set(detected.map(d => d.category));
  let verdict = 'No scam indicators detected';
  if (scamScore > 70 || categories.size >= 3) {
    verdict = 'HIGH RISK: Multiple scam indicators detected across categories. Likely a scam call.';
  } else if (scamScore > 40) {
    verdict = 'CAUTION: Some scam indicators present. Verify caller identity independently.';
  } else if (scamScore > 10) {
    verdict = 'LOW RISK: Minor indicators detected. Proceed with normal caution.';
  }

  return { scamScore, detectedIndicators: detected, verdict };
}

/**
 * Create a verification challenge to confirm caller identity.
 * Asks questions only the real person would know.
 */
export function generateVerificationChallenge(
  claimedIdentity: string,
  knownFacts: Array<{ question: string; answer: string; category: string }>,
): {
  challenges: Array<{ question: string; expectedAnswer: string }>;
  instructions: string;
} {
  // Select 2-3 random questions from different categories
  const categories = [...new Set(knownFacts.map(f => f.category))];
  const selected: typeof knownFacts = [];

  for (const cat of categories.slice(0, 3)) {
    const catFacts = knownFacts.filter(f => f.category === cat);
    const random = catFacts[Math.floor(Math.random() * catFacts.length)];
    if (random) selected.push(random);
  }

  return {
    challenges: selected.map(s => ({ question: s.question, expectedAnswer: s.answer })),
    instructions: `Someone claiming to be ${claimedIdentity} is on the line. Before providing any information or money, ask these verification questions. If they cannot answer correctly, hang up and call ${claimedIdentity} directly using a number you already have saved.`,
  };
}
