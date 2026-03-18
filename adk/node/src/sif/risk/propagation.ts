/**
 * ZAK Risk Propagation Engine -- implements the canonical node_risk formula.
 *
 * Formula (from spec):
 *   node_risk = base_risk * exposure_factor * exploitability
 *               * (1 - control_effectiveness) * privilege_amplifier
 *
 * All inputs are normalised to 0-1 before multiplication.
 * Output is scaled to 0-10 to match standard risk score conventions.
 *
 * TypeScript equivalent of zak/sif/risk/propagation.py.
 */

// ---------------------------------------------------------------------------
// RiskInputs
// ---------------------------------------------------------------------------

/**
 * Inputs required to compute node risk for a single asset.
 *
 * All float fields should be in range 0.0-1.0 unless noted.
 */
export interface RiskInputs {
  /** Inherent risk of the asset (derived from criticality). */
  baseRisk: number;
  /** How exposed is the asset (internal=0.2, external=0.6, internet=1.0). */
  exposureFactor: number;
  /** Highest exploitability score among associated vulnerabilities. */
  exploitability: number;
  /** Effectiveness of mitigating controls (0 = no controls, 1 = perfect). */
  controlEffectiveness: number;
  /** Risk amplifier from identity access levels (1.0 = baseline). */
  privilegeAmplifier: number;
}

// ---------------------------------------------------------------------------
// RiskOutput
// ---------------------------------------------------------------------------

/**
 * Result of a risk propagation computation.
 */
export interface RiskOutput {
  /** 0.0-1.0 before scaling. */
  rawScore: number;
  /** 0.0-10.0 (final output). */
  riskScore: number;
  /** low | medium | high | critical */
  riskLevel: string;
}

/**
 * Create a RiskOutput from a raw 0-1 score.
 */
function riskOutputFromRaw(raw: number): RiskOutput {
  const score = Math.round(raw * 10 * 100) / 100; // round to 2 decimals
  let level: string;
  if (score < 2.5) {
    level = "low";
  } else if (score < 5.0) {
    level = "medium";
  } else if (score < 7.5) {
    level = "high";
  } else {
    level = "critical";
  }
  return {
    rawScore: Math.round(raw * 10000) / 10000, // round to 4 decimals
    riskScore: score,
    riskLevel: level,
  };
}

// ---------------------------------------------------------------------------
// RiskPropagationEngine
// ---------------------------------------------------------------------------

/**
 * Computes risk scores using the ZAK canonical risk propagation formula.
 *
 * The engine is stateless -- all inputs are passed explicitly.
 * Integrate with the SIF graph adapter to pull live inputs.
 */
export class RiskPropagationEngine {
  /**
   * Apply the canonical risk formula.
   *
   * node_risk = base_risk * exposure_factor * exploitability
   *             * (1 - control_effectiveness) * privilege_amplifier
   *
   * Clamped to [0, 1] before scaling to [0, 10].
   */
  static compute(inputs: RiskInputs): RiskOutput {
    // Guard: control_effectiveness must be in [0,1]
    const controlReduction = Math.max(
      0.0,
      Math.min(1.0, 1.0 - inputs.controlEffectiveness),
    );

    let raw =
      inputs.baseRisk *
      inputs.exposureFactor *
      inputs.exploitability *
      controlReduction *
      inputs.privilegeAmplifier;

    // Clamp to [0, 1]
    raw = Math.max(0.0, Math.min(1.0, raw));

    return riskOutputFromRaw(raw);
  }

  /**
   * Convert a criticality label to a base_risk float.
   */
  static criticalityToBaseRisk(criticality: string): number {
    const mapping: Record<string, number> = {
      low: 0.2,
      medium: 0.4,
      high: 0.7,
      critical: 1.0,
    };
    return mapping[criticality.toLowerCase()] ?? 0.4;
  }

  /**
   * Convert an exposure_level label to an exposure_factor float.
   */
  static exposureToFactor(exposure: string): number {
    const mapping: Record<string, number> = {
      internal: 0.2,
      external: 0.6,
      internet_facing: 1.0,
    };
    return mapping[exposure.toLowerCase()] ?? 0.5;
  }

  /**
   * Convert a privilege_level label to a privilege_amplifier float.
   * Admin access amplifies risk; low privilege dampens it.
   */
  static privilegeToAmplifier(privilege: string): number {
    const mapping: Record<string, number> = {
      low: 0.5,
      medium: 0.8,
      high: 1.2,
      admin: 1.5,
    };
    return mapping[privilege.toLowerCase()] ?? 1.0;
  }
}
