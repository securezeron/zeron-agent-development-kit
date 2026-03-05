"""
Tests for the Risk Propagation Engine.
"""

import pytest

from zak.sif.risk.propagation import RiskInputs, RiskOutput, RiskPropagationEngine


class TestRiskPropagationEngine:
    def setup_method(self):
        self.engine = RiskPropagationEngine()

    def test_zero_inputs_gives_zero_risk(self):
        inputs = RiskInputs(
            base_risk=0.0,
            exposure_factor=0.0,
            exploitability=0.0,
            control_effectiveness=0.0,
            privilege_amplifier=1.0,
        )
        result = self.engine.compute(inputs)
        assert result.risk_score == 0.0
        assert result.risk_level == "low"

    def test_max_inputs_gives_critical_risk(self):
        inputs = RiskInputs(
            base_risk=1.0,
            exposure_factor=1.0,
            exploitability=1.0,
            control_effectiveness=0.0,
            privilege_amplifier=1.5,
        )
        result = self.engine.compute(inputs)
        assert result.risk_score >= 7.5
        assert result.risk_level == "critical"

    def test_perfect_control_eliminates_risk(self):
        inputs = RiskInputs(
            base_risk=1.0,
            exposure_factor=1.0,
            exploitability=1.0,
            control_effectiveness=1.0,  # perfect controls
            privilege_amplifier=1.5,
        )
        result = self.engine.compute(inputs)
        assert result.risk_score == 0.0

    def test_risk_score_bounded_to_10(self):
        inputs = RiskInputs(
            base_risk=1.0,
            exposure_factor=1.0,
            exploitability=1.0,
            control_effectiveness=0.0,
            privilege_amplifier=999.0,  # absurdly high
        )
        result = self.engine.compute(inputs)
        assert result.risk_score <= 10.0

    def test_criticality_to_base_risk_mapping(self):
        assert RiskPropagationEngine.criticality_to_base_risk("critical") == 1.0
        assert RiskPropagationEngine.criticality_to_base_risk("high") == 0.7
        assert RiskPropagationEngine.criticality_to_base_risk("medium") == 0.4
        assert RiskPropagationEngine.criticality_to_base_risk("low") == 0.2

    def test_exposure_to_factor_mapping(self):
        assert RiskPropagationEngine.exposure_to_factor("internet_facing") == 1.0
        assert RiskPropagationEngine.exposure_to_factor("external") == 0.6
        assert RiskPropagationEngine.exposure_to_factor("internal") == 0.2

    def test_privilege_to_amplifier_mapping(self):
        assert RiskPropagationEngine.privilege_to_amplifier("admin") == 1.5
        assert RiskPropagationEngine.privilege_to_amplifier("low") == 0.5

    def test_risk_level_bands(self):
        assert RiskOutput.from_raw(0.1).risk_level == "low"      # 1.0
        assert RiskOutput.from_raw(0.35).risk_level == "medium"  # 3.5
        assert RiskOutput.from_raw(0.6).risk_level == "high"     # 6.0
        assert RiskOutput.from_raw(0.85).risk_level == "critical" # 8.5
