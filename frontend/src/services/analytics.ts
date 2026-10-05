import { Investigation } from '../types';

export interface CumulativeAnalytics {
  totalSessionsAnalyzed: number;
  secureSessions: number;
  warningSessions: number;
  criticalSessions: number;
  analyzedCaptures: Record<string, {
    filename: string;
    sessions: number;
    analyzedAt: string;
    posture: string;
  }>;
}

const STORAGE_KEY = 'securemailscope.analytics';

// Baseline demonstration fleet numbers (104 sessions total: 81 secure, 14 warning, 9 critical)
const PROTOTYPE_BASELINE: CumulativeAnalytics = {
  totalSessionsAnalyzed: 104,
  secureSessions: 81,
  warningSessions: 14,
  criticalSessions: 9,
  analyzedCaptures: {
    // Initial simulated demo fleet baseline placeholder
    'demo-fleet-simulated-baseline': {
      filename: 'demo_fleet_simulation.pcap',
      sessions: 104,
      analyzedAt: '2026-09-30T00:00:00Z',
      posture: 'CRITICAL',
    },
  },
};

/**
 * Loads cumulative analytics from localStorage or initializes to the prototype baseline (104 sessions).
 */
export function getCumulativeAnalytics(): CumulativeAnalytics {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(PROTOTYPE_BASELINE));
      return { ...PROTOTYPE_BASELINE };
    }
    const parsed = JSON.parse(raw);
    if (
      typeof parsed.totalSessionsAnalyzed === 'number' &&
      typeof parsed.secureSessions === 'number' &&
      typeof parsed.warningSessions === 'number' &&
      typeof parsed.criticalSessions === 'number' &&
      typeof parsed.analyzedCaptures === 'object' &&
      parsed.analyzedCaptures !== null
    ) {
      return parsed as CumulativeAnalytics;
    }
    // Fallback if schema corrupted
    localStorage.setItem(STORAGE_KEY, JSON.stringify(PROTOTYPE_BASELINE));
    return { ...PROTOTYPE_BASELINE };
  } catch (e) {
    console.warn('Failed to read cumulative analytics from localStorage, using baseline:', e);
    return { ...PROTOTYPE_BASELINE };
  }
}

/**
 * Records a successfully analyzed unique real capture into the persistent cumulative analytics store.
 * Increments ONLY if:
 * 1. Capture is a real capture (not simulated demo)
 * 2. Capture has a valid SHA-256
 * 3. This SHA-256 has not previously been counted
 *
 * Returns updated CumulativeAnalytics and a boolean indicating if it was newly counted.
 */
export function recordAnalyzedCapture(investigation: Investigation): {
  analytics: CumulativeAnalytics;
  wasIncremented: boolean;
} {
  const current = getCumulativeAnalytics();

  // Guard against simulated demo data incrementing the counter
  if (investigation.is_simulated || investigation.data_source !== 'REAL_CAPTURE') {
    return { analytics: current, wasIncremented: false };
  }

  const sha = investigation.sha256_hash;
  if (!sha || sha.length < 16) {
    return { analytics: current, wasIncremented: false };
  }

  // Duplicate prevention check: if already counted, do not increment
  if (current.analyzedCaptures[sha]) {
    return { analytics: current, wasIncremented: false };
  }

  // Authoritative session counts from the current investigation
  const sessionsCount = investigation.summary.sessions_analyzed > 0 
    ? investigation.summary.sessions_analyzed 
    : (investigation.replays && investigation.replays.length > 0)
    ? investigation.replays.length 
    : (investigation.connections && investigation.connections.length > 0)
    ? investigation.connections.length
    : 1;

  // Use authoritative session classifications
  let newSecure = investigation.summary.secure_sessions || 0;
  let newWarning = investigation.summary.warning_sessions || 0;
  let newCritical = investigation.summary.critical_sessions || 0;

  // If summary buckets sum to 0 but sessions exist, derive from investigation security posture
  if (newSecure + newWarning + newCritical === 0 && sessionsCount > 0) {
    const postureStatus = investigation.security_posture?.status;
    if (postureStatus === 'CRITICAL' || postureStatus === 'HIGH_RISK') {
      newCritical = sessionsCount;
    } else if (postureStatus === 'NEEDS_ATTENTION') {
      newWarning = sessionsCount;
    } else {
      newSecure = sessionsCount;
    }
  }

  const updated: CumulativeAnalytics = {
    totalSessionsAnalyzed: current.totalSessionsAnalyzed + sessionsCount,
    secureSessions: current.secureSessions + newSecure,
    warningSessions: current.warningSessions + newWarning,
    criticalSessions: current.criticalSessions + newCritical,
    analyzedCaptures: {
      ...current.analyzedCaptures,
      [sha]: {
        filename: investigation.filename,
        sessions: sessionsCount,
        analyzedAt: new Date().toISOString(),
        posture: investigation.security_posture?.status || 'UNKNOWN',
      },
    },
  };

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (e) {
    console.warn('Failed to persist cumulative analytics:', e);
  }

  return { analytics: updated, wasIncremented: true };
}

/**
 * Resets cumulative analytics back to the prototype baseline (104 sessions).
 * Available for testing and internal development via window.__resetSecureMailScopeAnalytics().
 */
export function resetCumulativeAnalytics(): CumulativeAnalytics {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(PROTOTYPE_BASELINE));
  } catch (e) {
    console.warn('Failed to reset cumulative analytics:', e);
  }
  return { ...PROTOTYPE_BASELINE };
}

// Attach development helper to window for development/testing
if (typeof window !== 'undefined') {
  (window as unknown as { __resetSecureMailScopeAnalytics: () => CumulativeAnalytics }).__resetSecureMailScopeAnalytics = resetCumulativeAnalytics;
}
