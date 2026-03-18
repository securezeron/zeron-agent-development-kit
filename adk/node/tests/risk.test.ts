/**
 * ZAK Risk Propagation Engine Tests (Phase 3)
 *
 * Covers:
 * - compute() with various inputs
 * - Risk levels: low, medium, high, critical
 * - Clamping to [0,1]
 * - Helper methods: criticalityToBaseRisk, exposureToFactor, privilegeToAmplifier
 * - Zero inputs
 * - Max inputs
 * - control_effectiveness boundaries
 * - Edge cases and floating point handling
 */

import { describe, it, expect } from "vitest";

import {
  RiskPropagationEngine,
  type RiskInputs,
  type RiskOutput,
} from "../src/sif/risk/propagation.js";

// ===========================================================================
// compute() — basic formula verification
// ===========================================================================

describe("RiskPropagationEngine.compute()", () => {
  it("computes risk for a typical medium-risk scenario", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.4,
      exposureFactor: 0.6,
      exploitability: 0.5,
      controlEffectiveness: 0.5,
      privilegeAmplifier: 0.8,
    };

    const result = RiskPropagationEngine.compute(inputs);

    // raw = 0.4 * 0.6 * 0.5 * (1-0.5) * 0.8 = 0.4 * 0.6 * 0.5 * 0.5 * 0.8 = 0.048
    expect(result.rawScore).toBeCloseTo(0.048, 3);
    expect(result.riskScore).toBeCloseTo(0.48, 1);
    expect(result.riskLevel).toBe("low");
  });

  it("computes risk for a high-risk scenario", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,         // critical
      exposureFactor: 1.0,   // internet-facing
      exploitability: 0.9,
      controlEffectiveness: 0.1, // poor controls
      privilegeAmplifier: 1.5,  // admin
    };

    const result = RiskPropagationEngine.compute(inputs);

    // raw = 1.0 * 1.0 * 0.9 * 0.9 * 1.5 = 1.215 -> clamped to 1.0
    expect(result.rawScore).toBe(1.0);
    expect(result.riskScore).toBe(10.0);
    expect(result.riskLevel).toBe("critical");
  });

  it("computes risk for a low-risk scenario", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.2,         // low criticality
      exposureFactor: 0.2,   // internal
      exploitability: 0.3,
      controlEffectiveness: 0.7, // good controls
      privilegeAmplifier: 0.5,  // low privilege
    };

    const result = RiskPropagationEngine.compute(inputs);

    // raw = 0.2 * 0.2 * 0.3 * 0.3 * 0.5 = 0.0018
    expect(result.rawScore).toBeCloseTo(0.0018, 3);
    expect(result.riskScore).toBeCloseTo(0.02, 1);
    expect(result.riskLevel).toBe("low");
  });
});

// ===========================================================================
// Risk levels
// ===========================================================================

describe("Risk levels", () => {
  it("classifies low risk (score < 2.5)", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.2,
      exposureFactor: 0.2,
      exploitability: 0.5,
      controlEffectiveness: 0.5,
      privilegeAmplifier: 0.5,
    };
    const result = RiskPropagationEngine.compute(inputs);
    expect(result.riskLevel).toBe("low");
    expect(result.riskScore).toBeLessThan(2.5);
  });

  it("classifies medium risk (2.5 <= score < 5.0)", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.7,
      exposureFactor: 0.6,
      exploitability: 0.7,
      controlEffectiveness: 0.1,
      privilegeAmplifier: 1.2,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // raw = 0.7 * 0.6 * 0.7 * 0.9 * 1.2 = 0.31752
    expect(result.riskLevel).toBe("medium");
    expect(result.riskScore).toBeGreaterThanOrEqual(2.5);
    expect(result.riskScore).toBeLessThan(5.0);
  });

  it("classifies high risk (5.0 <= score < 7.5)", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 0.8,
      controlEffectiveness: 0.2,
      privilegeAmplifier: 0.8,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // raw = 1.0 * 1.0 * 0.8 * 0.8 * 0.8 = 0.512
    expect(result.riskLevel).toBe("high");
    expect(result.riskScore).toBeGreaterThanOrEqual(5.0);
    expect(result.riskScore).toBeLessThan(7.5);
  });

  it("classifies critical risk (score >= 7.5)", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 0.9,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // raw = 1.0 * 1.0 * 0.9 * 1.0 * 1.5 = 1.35 -> clamped to 1.0
    expect(result.riskLevel).toBe("critical");
    expect(result.riskScore).toBeGreaterThanOrEqual(7.5);
  });
});

// ===========================================================================
// Clamping
// ===========================================================================

describe("Clamping", () => {
  it("clamps raw score to [0, 1] when result exceeds 1.0", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // raw = 1.0 * 1.0 * 1.0 * 1.0 * 1.5 = 1.5 -> clamped to 1.0
    expect(result.rawScore).toBe(1.0);
    expect(result.riskScore).toBe(10.0);
  });

  it("clamps raw score to [0, 1] when result is exactly 1.0", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.0,
    };
    const result = RiskPropagationEngine.compute(inputs);

    expect(result.rawScore).toBe(1.0);
    expect(result.riskScore).toBe(10.0);
  });

  it("returns zero when any factor is zero", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);

    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
    expect(result.riskLevel).toBe("low");
  });
});

// ===========================================================================
// Zero inputs
// ===========================================================================

describe("Zero inputs", () => {
  it("returns zero risk when all inputs are zero", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.0,
      exposureFactor: 0.0,
      exploitability: 0.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 0.0,
    };
    const result = RiskPropagationEngine.compute(inputs);

    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
    expect(result.riskLevel).toBe("low");
  });

  it("returns zero risk when baseRisk is zero", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);
    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
  });

  it("returns zero risk when exploitability is zero", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 0.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);
    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
  });

  it("returns zero risk when exposureFactor is zero", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 0.0,
      exploitability: 1.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);
    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
  });
});

// ===========================================================================
// Max inputs
// ===========================================================================

describe("Max inputs", () => {
  it("returns max risk when all factors maximize risk", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // 1.0 * 1.0 * 1.0 * 1.0 * 1.5 = 1.5 -> clamped to 1.0
    expect(result.rawScore).toBe(1.0);
    expect(result.riskScore).toBe(10.0);
    expect(result.riskLevel).toBe("critical");
  });
});

// ===========================================================================
// control_effectiveness boundaries
// ===========================================================================

describe("controlEffectiveness boundaries", () => {
  it("zero effectiveness means no risk reduction", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.5,
      exposureFactor: 0.5,
      exploitability: 0.5,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.0,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // raw = 0.5 * 0.5 * 0.5 * 1.0 * 1.0 = 0.125
    expect(result.rawScore).toBeCloseTo(0.125, 3);
  });

  it("perfect effectiveness (1.0) eliminates all risk", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 1.0,
      privilegeAmplifier: 1.5,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // (1 - 1.0) = 0, so raw = 0
    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
    expect(result.riskLevel).toBe("low");
  });

  it("effectiveness > 1.0 is clamped (treated as 1.0)", () => {
    const inputs: RiskInputs = {
      baseRisk: 1.0,
      exposureFactor: 1.0,
      exploitability: 1.0,
      controlEffectiveness: 1.5, // exceeds 1.0
      privilegeAmplifier: 1.0,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // controlReduction = max(0, min(1, 1 - 1.5)) = max(0, min(1, -0.5)) = 0
    expect(result.rawScore).toBe(0.0);
    expect(result.riskScore).toBe(0.0);
  });

  it("effectiveness < 0.0 is clamped (treated as 0.0)", () => {
    const inputs: RiskInputs = {
      baseRisk: 0.5,
      exposureFactor: 0.5,
      exploitability: 0.5,
      controlEffectiveness: -0.5, // below 0.0
      privilegeAmplifier: 1.0,
    };
    const result = RiskPropagationEngine.compute(inputs);

    // controlReduction = max(0, min(1, 1 - (-0.5))) = max(0, min(1, 1.5)) = 1.0
    // raw = 0.5 * 0.5 * 0.5 * 1.0 * 1.0 = 0.125
    expect(result.rawScore).toBeCloseTo(0.125, 3);
  });

  it("half effectiveness reduces risk by 50%", () => {
    const baseInputs: RiskInputs = {
      baseRisk: 0.5,
      exposureFactor: 0.5,
      exploitability: 0.5,
      controlEffectiveness: 0.0,
      privilegeAmplifier: 1.0,
    };
    const halfInputs: RiskInputs = {
      ...baseInputs,
      controlEffectiveness: 0.5,
    };

    const baseResult = RiskPropagationEngine.compute(baseInputs);
    const halfResult = RiskPropagationEngine.compute(halfInputs);

    // Half effectiveness should give exactly half the raw score
    expect(halfResult.rawScore).toBeCloseTo(baseResult.rawScore * 0.5, 3);
  });
});

// ===========================================================================
// Helper methods
// ===========================================================================

describe("criticalityToBaseRisk()", () => {
  it("maps low to 0.2", () => {
    expect(RiskPropagationEngine.criticalityToBaseRisk("low")).toBe(0.2);
  });

  it("maps medium to 0.4", () => {
    expect(RiskPropagationEngine.criticalityToBaseRisk("medium")).toBe(0.4);
  });

  it("maps high to 0.7", () => {
    expect(RiskPropagationEngine.criticalityToBaseRisk("high")).toBe(0.7);
  });

  it("maps critical to 1.0", () => {
    expect(RiskPropagationEngine.criticalityToBaseRisk("critical")).toBe(1.0);
  });

  it("is case-insensitive", () => {
    expect(RiskPropagationEngine.criticalityToBaseRisk("HIGH")).toBe(0.7);
    expect(RiskPropagationEngine.criticalityToBaseRisk("Critical")).toBe(1.0);
  });

  it("returns 0.4 for unknown values", () => {
    expect(RiskPropagationEngine.criticalityToBaseRisk("unknown")).toBe(0.4);
  });
});

describe("exposureToFactor()", () => {
  it("maps internal to 0.2", () => {
    expect(RiskPropagationEngine.exposureToFactor("internal")).toBe(0.2);
  });

  it("maps external to 0.6", () => {
    expect(RiskPropagationEngine.exposureToFactor("external")).toBe(0.6);
  });

  it("maps internet_facing to 1.0", () => {
    expect(RiskPropagationEngine.exposureToFactor("internet_facing")).toBe(1.0);
  });

  it("is case-insensitive", () => {
    expect(RiskPropagationEngine.exposureToFactor("INTERNAL")).toBe(0.2);
    expect(RiskPropagationEngine.exposureToFactor("Internet_Facing")).toBe(1.0);
  });

  it("returns 0.5 for unknown values", () => {
    expect(RiskPropagationEngine.exposureToFactor("unknown")).toBe(0.5);
  });
});

describe("privilegeToAmplifier()", () => {
  it("maps low to 0.5", () => {
    expect(RiskPropagationEngine.privilegeToAmplifier("low")).toBe(0.5);
  });

  it("maps medium to 0.8", () => {
    expect(RiskPropagationEngine.privilegeToAmplifier("medium")).toBe(0.8);
  });

  it("maps high to 1.2", () => {
    expect(RiskPropagationEngine.privilegeToAmplifier("high")).toBe(1.2);
  });

  it("maps admin to 1.5", () => {
    expect(RiskPropagationEngine.privilegeToAmplifier("admin")).toBe(1.5);
  });

  it("is case-insensitive", () => {
    expect(RiskPropagationEngine.privilegeToAmplifier("ADMIN")).toBe(1.5);
    expect(RiskPropagationEngine.privilegeToAmplifier("High")).toBe(1.2);
  });

  it("returns 1.0 for unknown values", () => {
    expect(RiskPropagationEngine.privilegeToAmplifier("unknown")).toBe(1.0);
  });
});

// ===========================================================================
// End-to-end with helpers
// ===========================================================================

describe("End-to-end with helpers", () => {
  it("computes risk using label-based helpers", () => {
    const inputs: RiskInputs = {
      baseRisk: RiskPropagationEngine.criticalityToBaseRisk("critical"),
      exposureFactor: RiskPropagationEngine.exposureToFactor("internet_facing"),
      exploitability: 0.9,
      controlEffectiveness: 0.3,
      privilegeAmplifier: RiskPropagationEngine.privilegeToAmplifier("admin"),
    };
    const result = RiskPropagationEngine.compute(inputs);

    // baseRisk=1.0, exposureFactor=1.0, expl=0.9, ctrl=(1-0.3)=0.7, priv=1.5
    // raw = 1.0 * 1.0 * 0.9 * 0.7 * 1.5 = 0.945
    expect(result.rawScore).toBeCloseTo(0.945, 2);
    expect(result.riskScore).toBeCloseTo(9.45, 1);
    expect(result.riskLevel).toBe("critical");
  });

  it("computes risk for a well-protected internal asset", () => {
    const inputs: RiskInputs = {
      baseRisk: RiskPropagationEngine.criticalityToBaseRisk("low"),
      exposureFactor: RiskPropagationEngine.exposureToFactor("internal"),
      exploitability: 0.2,
      controlEffectiveness: 0.9,
      privilegeAmplifier: RiskPropagationEngine.privilegeToAmplifier("low"),
    };
    const result = RiskPropagationEngine.compute(inputs);

    // baseRisk=0.2, exposure=0.2, expl=0.2, ctrl=(1-0.9)=0.1, priv=0.5
    // raw = 0.2 * 0.2 * 0.2 * 0.1 * 0.5 = 0.0004
    expect(result.rawScore).toBeCloseTo(0.0004, 3);
    expect(result.riskScore).toBeLessThan(0.1);
    expect(result.riskLevel).toBe("low");
  });
});
