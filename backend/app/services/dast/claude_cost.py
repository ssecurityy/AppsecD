"""Claude DAST cost tracking — token counting, budget enforcement, usage recording."""
import json
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Pricing per 1M tokens (USD) — March 2026
MODEL_PRICING = {
    "claude-opus-4-6": {"input": 15.00, "output": 75.00, "cached_input": 1.50},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00, "cached_input": 0.30},
    "claude-haiku-4-5-20251001": {"input": 1.00, "output": 5.00, "cached_input": 0.10},
    # Batch pricing (50% discount)
    "claude-opus-4-6-batch": {"input": 7.50, "output": 37.50, "cached_input": 0.75},
    "claude-sonnet-4-6-batch": {"input": 1.50, "output": 7.50, "cached_input": 0.15},
    "claude-haiku-4-5-20251001-batch": {"input": 0.50, "output": 2.50, "cached_input": 0.05},
}

# Scan mode → model mapping
SCAN_MODE_MODELS = {
    "quick": {
        "crawl": "claude-haiku-4-5-20251001",
        "recon": "claude-haiku-4-5-20251001",
        "checks": "claude-haiku-4-5-20251001",
        "dynamic": "claude-haiku-4-5-20251001",
        "verify": "claude-haiku-4-5-20251001",
    },
    "standard": {
        "crawl": "claude-haiku-4-5-20251001",
        "recon": "claude-haiku-4-5-20251001",
        "checks": "claude-sonnet-4-6",
        "dynamic": "claude-sonnet-4-6",
        "verify": "claude-sonnet-4-6",
    },
    "deep": {
        "crawl": "claude-sonnet-4-6",
        "recon": "claude-sonnet-4-6",
        "checks": "claude-sonnet-4-6",
        "dynamic": "claude-opus-4-6",
        "verify": "claude-opus-4-6",
    },
}


@dataclass
class CostTracker:
    """Track token usage and costs for a single scan session."""

    scan_id: str
    project_id: str
    scan_mode: str = "standard"

    # Cumulative counters
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cached_input_tokens: int = 0
    total_thinking_tokens: int = 0
    total_api_calls: int = 0
    total_cost_usd: float = 0.0

    # Per-model breakdown
    model_calls: dict = field(default_factory=dict)
    model_tokens: dict = field(default_factory=dict)
    model_costs: dict = field(default_factory=dict)

    # Budget limits
    max_cost_usd: float = 20.0
    max_api_calls: int = 200

    # Phase tracking
    phase_costs: dict = field(default_factory=dict)
    current_phase: str = ""

    def get_model_for_phase(self, phase: str) -> str:
        """Return the appropriate model for the current scan mode and phase."""
        mode_map = SCAN_MODE_MODELS.get(self.scan_mode, SCAN_MODE_MODELS["standard"])
        # Map detailed phase names to model phase keys
        phase_key_map = {
            "crawling": "crawl",
            "recon": "recon",
            "automated_checks": "checks",
            "dynamic_testing": "dynamic",
            "llm_testing": "dynamic",
            "business_logic": "dynamic",
            "verification": "verify",
            "test_generation": "checks",
        }
        key = phase_key_map.get(phase, "checks")
        return mode_map.get(key, "claude-sonnet-4-6")

    def record_usage(self, model: str, input_tokens: int, output_tokens: int,
                     cached_input_tokens: int = 0, thinking_tokens: int = 0) -> None:
        """Record token usage from a single API call."""
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_cached_input_tokens += cached_input_tokens
        self.total_thinking_tokens += thinking_tokens
        self.total_api_calls += 1

        # Per-model tracking
        if model not in self.model_calls:
            self.model_calls[model] = 0
            self.model_tokens[model] = {"input": 0, "output": 0, "cached": 0}
            self.model_costs[model] = 0.0
        self.model_calls[model] += 1
        self.model_tokens[model]["input"] += input_tokens
        self.model_tokens[model]["output"] += output_tokens
        self.model_tokens[model]["cached"] += cached_input_tokens

        # Calculate cost for this call
        pricing = MODEL_PRICING.get(model, MODEL_PRICING["claude-sonnet-4-6"])
        cost = (
            (input_tokens - cached_input_tokens) * pricing["input"] / 1_000_000
            + cached_input_tokens * pricing["cached_input"] / 1_000_000
            + (output_tokens + thinking_tokens) * pricing["output"] / 1_000_000
        )
        self.total_cost_usd += cost
        self.model_costs[model] = self.model_costs.get(model, 0.0) + cost

        # Phase cost tracking
        if self.current_phase:
            self.phase_costs[self.current_phase] = self.phase_costs.get(self.current_phase, 0.0) + cost

    def set_phase(self, phase: str) -> None:
        """Update current phase for cost attribution."""
        self.current_phase = phase

    def is_budget_exceeded(self) -> bool:
        """Check if scan has exceeded its budget."""
        return self.total_cost_usd >= self.max_cost_usd or self.total_api_calls >= self.max_api_calls

    def budget_remaining_usd(self) -> float:
        """Return remaining budget in USD."""
        return max(0.0, self.max_cost_usd - self.total_cost_usd)

    def calls_remaining(self) -> int:
        """Return remaining API calls before budget limit."""
        return max(0, self.max_api_calls - self.total_api_calls)

    def should_downgrade_model(self) -> bool:
        """Return True if we should switch to a cheaper model to stay in budget."""
        # Downgrade when >70% of budget is spent
        return self.total_cost_usd > self.max_cost_usd * 0.7

    def get_downgraded_model(self, current_model: str) -> str:
        """Return a cheaper model alternative."""
        downgrade_chain = {
            "claude-opus-4-6": "claude-sonnet-4-6",
            "claude-sonnet-4-6": "claude-haiku-4-5-20251001",
            "claude-haiku-4-5-20251001": "claude-haiku-4-5-20251001",  # Can't go lower
        }
        return downgrade_chain.get(current_model, current_model)

    def to_dict(self) -> dict:
        """Serialize for Redis/API response."""
        return {
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "scan_mode": self.scan_mode,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cached_input_tokens": self.total_cached_input_tokens,
            "total_thinking_tokens": self.total_thinking_tokens,
            "total_api_calls": self.total_api_calls,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "budget_remaining_usd": round(self.budget_remaining_usd(), 4),
            "calls_remaining": self.calls_remaining(),
            "model_calls": self.model_calls,
            "model_costs": {k: round(v, 4) for k, v in self.model_costs.items()},
            "phase_costs": {k: round(v, 4) for k, v in self.phase_costs.items()},
            "is_budget_exceeded": self.is_budget_exceeded(),
        }


def estimate_scan_cost(scan_mode: str, num_endpoints: int = 20, num_checks: int = 68) -> dict:
    """Estimate cost before starting a scan.

    Returns estimated cost range, model breakdown, and approximate time.
    """
    # Rough estimates based on typical scan patterns
    estimates = {
        "quick": {
            "model": "claude-haiku-4-5-20251001",
            "estimated_api_calls": min(num_checks + 10, 80),
            "avg_input_per_call": 3000,
            "avg_output_per_call": 500,
            "estimated_minutes": 3,
        },
        "standard": {
            "model": "claude-sonnet-4-6",
            "estimated_api_calls": num_checks + num_endpoints * 3 + 20,
            "avg_input_per_call": 5000,
            "avg_output_per_call": 1000,
            "estimated_minutes": 10,
        },
        "deep": {
            "model": "claude-opus-4-6",
            "estimated_api_calls": num_checks + num_endpoints * 5 + 40,
            "avg_input_per_call": 8000,
            "avg_output_per_call": 2000,
            "estimated_minutes": 25,
        },
    }

    est = estimates.get(scan_mode, estimates["standard"])
    pricing = MODEL_PRICING.get(est["model"], MODEL_PRICING["claude-sonnet-4-6"])

    total_input = est["estimated_api_calls"] * est["avg_input_per_call"]
    total_output = est["estimated_api_calls"] * est["avg_output_per_call"]

    cost_low = (total_input * pricing["input"] / 1_000_000 + total_output * pricing["output"] / 1_000_000) * 0.5  # With caching
    cost_high = total_input * pricing["input"] / 1_000_000 + total_output * pricing["output"] / 1_000_000

    return {
        "scan_mode": scan_mode,
        "primary_model": est["model"],
        "estimated_api_calls": est["estimated_api_calls"],
        "estimated_cost_low_usd": round(cost_low, 2),
        "estimated_cost_high_usd": round(cost_high, 2),
        "estimated_minutes": est["estimated_minutes"],
        "note": "Actual cost depends on target complexity, WAF evasion attempts, and number of findings.",
    }
