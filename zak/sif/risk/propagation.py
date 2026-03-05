"""
ZAK Risk Propagation Engine — implements the canonical node_risk formula.

Formula (from spec):
  node_risk = base_risk × exposure_factor × exploitability
              × (1 - control_effectiveness) × privilege_amplifier

All inputs are normalised to 0–1 before multiplication.
Output is scaled to 0–10 to match standard risk score conventions.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskInputs:
    """
    Inputs required to compute node risk for a single asset.

    All float fields should be in range 0.0–1.0 unless noted.
    """
    base_risk: float          # Inherent risk of the asset (derived from criticality)
    exposure_factor: float    # How exposed is the asset (internal=0.2, external=0.6, internet=1.0)
    exploitability: float     # Highest exploitability score among associated vulnerabilities
    control_effectiveness: float  # Effectiveness of mitigating controls (0 = no controls, 1 = perfect)
    privilege_amplifier: float    # Risk amplifier from identity access levels (1.0 = baseline)


@dataclass
class RiskOutput:
    """Result of a risk propagation computation."""
    raw_score: float          # 0.0–1.0 before scaling
    risk_score: float         # 0.0–10.0 (final output)
    risk_level: str           # low | medium | high | critical

    @classmethod
    def from_raw(cls, raw: float) -> RiskOutput:
        score = round(raw * 10, 2)
        if score < 2.5:
            level = "low"
        elif score < 5.0:
            level = "medium"
        elif score < 7.5:
            level = "high"
        else:
            level = "critical"
        return cls(raw_score=round(raw, 4), risk_score=score, risk_level=level)


class RiskPropagationEngine:
    """
    Computes risk scores using the ZAK canonical risk propagation formula.

    The engine is stateless — all inputs are passed explicitly.
    Integrate with the SIF graph adapter to pull live inputs.
    """

    @staticmethod
    def compute(inputs: RiskInputs) -> RiskOutput:
        """
        Apply the canonical risk formula.

        node_risk = base_risk × exposure_factor × exploitability
                    × (1 - control_effectiveness) × privilege_amplifier

        Clamped to [0, 1] before scaling to [0, 10].
        """
        # Guard: control_effectiveness must be in [0,1]
        control_reduction = max(0.0, min(1.0, 1.0 - inputs.control_effectiveness))

        raw = (
            inputs.base_risk
            * inputs.exposure_factor
            * inputs.exploitability
            * control_reduction
            * inputs.privilege_amplifier
        )

        # Clamp to [0, 1]
        raw = max(0.0, min(1.0, raw))
        return RiskOutput.from_raw(raw)

    @staticmethod
    def criticality_to_base_risk(criticality: str) -> float:
        """Convert a criticality label to a base_risk float."""
        mapping = {"low": 0.2, "medium": 0.4, "high": 0.7, "critical": 1.0}
        return mapping.get(criticality.lower(), 0.4)

    @staticmethod
    def exposure_to_factor(exposure: str) -> float:
        """Convert an exposure_level label to an exposure_factor float."""
        mapping = {"internal": 0.2, "external": 0.6, "internet_facing": 1.0}
        return mapping.get(exposure.lower(), 0.5)

    @staticmethod
    def privilege_to_amplifier(privilege: str) -> float:
        """
        Convert a privilege_level label to a privilege_amplifier float.
        Admin access amplifies risk; low privilege dampens it.
        """
        mapping = {"low": 0.5, "medium": 0.8, "high": 1.2, "admin": 1.5}
        return mapping.get(privilege.lower(), 1.0)
