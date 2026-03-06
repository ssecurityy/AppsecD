"""Claude DAST Agent — core orchestrator for AI-powered security testing.

Uses Claude API tool_use to drive intelligent DAST scanning:
crawling, testing, verification, and finding generation.
"""
import json
import logging
import time
from typing import Callable

from .claude_tools import build_all_tools
from .claude_prompts import (
    SYSTEM_PROMPT_SCAN,
    SYSTEM_PROMPT_RETEST,
    SYSTEM_PROMPT_CRAWL_ONLY,
    SYSTEM_PROMPT_GENERATE_CHECKS,
    AUTH_INSTRUCTIONS_TEMPLATE,
    AUTH_INSTRUCTIONS_NONE,
)
from .claude_cost import CostTracker
from .runner import ALL_CHECKS

logger = logging.getLogger(__name__)

# Max tool_use loop iterations to prevent runaway
MAX_TOOL_LOOP_ITERATIONS = 300
# Max response tokens per API call
MAX_TOKENS = 16384


class ClaudeDastAgent:
    """Orchestrates Claude-powered DAST scanning via tool_use API loop."""

    def __init__(
        self,
        anthropic_api_key: str,
        project_id: str,
        scan_id: str,
        scan_mode: str = "standard",
        max_cost_usd: float = 20.0,
        max_api_calls: int = 200,
        auth_headers: dict | None = None,
        auth_type: str = "none",
        organization_id: str = "",
    ):
        from anthropic import Anthropic

        self.client = Anthropic(api_key=anthropic_api_key)
        self.project_id = project_id
        self.scan_id = scan_id
        self.scan_mode = scan_mode
        self.auth_headers = auth_headers or {}
        self.auth_type = auth_type
        self.organization_id = organization_id

        # Cost tracking
        self.cost = CostTracker(
            scan_id=scan_id,
            project_id=project_id,
            scan_mode=scan_mode,
            max_cost_usd=max_cost_usd,
            max_api_calls=max_api_calls,
        )

        # Build tools from ALL_CHECKS registry
        check_names = [name for name, _ in ALL_CHECKS]
        self.tools = build_all_tools(check_names)

        # Results accumulated during scan
        self.findings: list[dict] = []
        self.crawl_results: list[dict] = []
        self.new_test_cases: list[dict] = []
        self.pentest_options: list[dict] = []
        self.activity_log: list[dict] = []

        # Progress callback
        self._progress_callback: Callable | None = None
        self._executor = None  # Set by caller
        self._start_time: float = time.time()

    def set_executor(self, executor) -> None:
        """Set the tool executor instance."""
        self._executor = executor

    def set_progress_callback(self, callback: Callable) -> None:
        """Set callback for progress updates: callback(progress_dict)."""
        self._progress_callback = callback

    def _emit_progress(self, phase: str, message: str, **extra) -> None:
        """Emit progress update to Redis via callback."""
        entry = {"ts": time.time(), "msg": message, "type": extra.get("log_type", "info")}
        self.activity_log.append(entry)
        if len(self.activity_log) > 50:
            self.activity_log = self.activity_log[-50:]

        if self._progress_callback:
            progress = {
                "status": "running",
                "current_phase": phase,
                "current_activity": message,
                "findings_so_far": len(self.findings),
                "findings_by_severity": self._severity_counts(),
                "pages_crawled": len(self.crawl_results),
                "new_test_cases": len(self.new_test_cases),
                "activity_log": self.activity_log[-20:],
                "pending_pentest_options": self.pentest_options,
                "cost": self.cost.to_dict(),
                # Live crawl results for real-time display (last 50)
                "live_crawl_results": self.crawl_results[-50:] if self.crawl_results else [],
                # Progress percentage and ETA
                "progress_pct": self._calculate_progress_pct(phase),
                "eta_seconds": self._estimate_eta(phase),
                **extra,
            }
            self._progress_callback(progress)

    def _severity_counts(self) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    # Phase weights for progress percentage
    _PHASE_WEIGHTS = {
        "initializing": 2, "crawling": 20, "recon": 10,
        "automated_checks": 25, "dynamic_testing": 20,
        "llm_testing": 10, "business_logic": 5,
        "verification": 5, "test_generation": 2, "done": 1,
    }
    _PHASE_ORDER = list(_PHASE_WEIGHTS.keys())

    def _calculate_progress_pct(self, current_phase: str) -> int:
        """Approximate progress percentage based on scan phase."""
        total = 0
        for p in self._PHASE_ORDER:
            if p == current_phase:
                total += self._PHASE_WEIGHTS.get(p, 5) // 2  # midway through current
                break
            total += self._PHASE_WEIGHTS.get(p, 5)
        return min(max(total, 1), 99)

    def _estimate_eta(self, current_phase: str) -> int | None:
        """Estimate seconds remaining based on elapsed time and progress."""
        pct = self._calculate_progress_pct(current_phase)
        if pct <= 2:
            return None
        elapsed = time.time() - self._start_time
        rate = elapsed / pct
        remaining = 100 - pct
        return max(int(rate * remaining), 0)

    async def run_intelligent_scan(
        self,
        target_url: str,
        project_context: dict,
        session_context: dict | None = None,
    ) -> dict:
        """Execute full Claude-powered DAST scan.

        Args:
            target_url: Target URL to scan.
            project_context: Dict with keys: testing_scope, stack_profile,
                existing_findings, test_cases, crawl_data.
            session_context: Previous session messages (for retest continuity).

        Returns:
            Dict with: findings, crawl_results, new_test_cases, cost, duration.
        """
        start_time = time.time()
        check_names = [name for name, _ in ALL_CHECKS]

        # Retrieve RAG learnings if available
        past_learnings_text = ""
        try:
            from urllib.parse import urlparse as _urlparse
            domain = _urlparse(target_url).hostname or ""
            from .claude_rag import retrieve_learnings, get_domain_profile, format_learnings_for_prompt
            from app.core.database import AsyncSessionLocal
            import asyncio

            async def _fetch_rag():
                async with AsyncSessionLocal() as db:
                    learnings = await retrieve_learnings(
                        db, domain=domain,
                        technology_stack=project_context.get("stack_profile"),
                        organization_id=self.organization_id or None,
                    )
                    profile = await get_domain_profile(db, domain=domain, organization_id=self.organization_id or None)
                    return format_learnings_for_prompt(learnings, profile)

            past_learnings_text = asyncio.get_event_loop().run_until_complete(_fetch_rag())
        except Exception as e:
            logger.debug("RAG retrieval skipped: %s", e)

        # Build auth instructions
        auth_instructions = AUTH_INSTRUCTIONS_NONE
        if self.auth_headers and self.auth_type != "none":
            auth_instructions = AUTH_INSTRUCTIONS_TEMPLATE.format(auth_type=self.auth_type)

        # Build system prompt
        system_prompt = SYSTEM_PROMPT_SCAN.format(
            target_url=target_url,
            testing_scope=project_context.get("testing_scope", "Target URL and same-origin resources"),
            include_subdomains=project_context.get("include_subdomains", False),
            stack_profile=json.dumps(project_context.get("stack_profile", {}), indent=1),
            scan_mode=self.scan_mode,
            session_summary=json.dumps(session_context.get("summary", "No previous session"), default=str) if session_context else "No previous session",
            existing_findings=self._format_existing_findings(project_context.get("existing_findings", [])),
            false_positives=self._format_false_positives(project_context.get("existing_findings", [])),
            num_checks=len(check_names),
            available_checks=", ".join(check_names),
            max_api_calls=self.cost.max_api_calls,
            past_learnings=past_learnings_text,
            auth_instructions=auth_instructions,
        )

        # Initial user message
        initial_message = (
            f"Begin comprehensive DAST assessment of {target_url}. "
            f"Scan mode: {self.scan_mode}. "
            f"Start with Phase 1: Crawling to discover the complete attack surface."
        )

        messages = []
        # Restore session context if available
        if session_context and session_context.get("messages"):
            messages = session_context["messages"][-20:]  # Keep last 20 messages for context
            messages.append({"role": "user", "content": initial_message})
        else:
            messages = [{"role": "user", "content": initial_message}]

        self._emit_progress("crawling", f"Starting Claude AI scan of {target_url}")
        self.cost.set_phase("crawling")

        # Execute tool_use loop
        try:
            messages = await self._tool_use_loop(
                system_prompt=system_prompt,
                messages=messages,
                max_iterations=MAX_TOOL_LOOP_ITERATIONS,
            )
        except BudgetExceededError:
            logger.warning("Scan %s exceeded budget, stopping gracefully", self.scan_id)
            self._emit_progress("done", "Scan stopped: budget limit reached")
        except Exception as e:
            logger.exception("Claude scan %s failed: %s", self.scan_id, e)
            self._emit_progress("done", f"Scan error: {str(e)[:200]}")

        duration = round(time.time() - start_time, 1)

        self._emit_progress("done", f"Scan complete: {len(self.findings)} findings in {duration}s")

        return {
            "findings": self.findings,
            "crawl_results": self.crawl_results,
            "new_test_cases": self.new_test_cases,
            "pentest_options": self.pentest_options,
            "cost": self.cost.to_dict(),
            "duration_seconds": duration,
            "messages": messages[-30:],  # Keep last 30 for session persistence
            "activity_log": self.activity_log,
        }

    async def retest_findings(
        self,
        target_url: str,
        findings_to_retest: list[dict],
        project_context: dict,
        session_context: dict | None = None,
    ) -> dict:
        """Retest specific findings using Claude with session context."""
        start_time = time.time()

        system_prompt = SYSTEM_PROMPT_RETEST.format(
            target_url=target_url,
            project_name=project_context.get("project_name", "Unknown"),
            session_summary=json.dumps(session_context.get("summary", ""), default=str) if session_context else "",
            findings_to_retest=json.dumps(findings_to_retest, indent=2, default=str),
        )

        messages = [{"role": "user", "content": f"Retest {len(findings_to_retest)} findings against {target_url}. Start now."}]

        self._emit_progress("verification", f"Retesting {len(findings_to_retest)} findings")

        try:
            messages = await self._tool_use_loop(
                system_prompt=system_prompt,
                messages=messages,
                max_iterations=len(findings_to_retest) * 15 + 20,
            )
        except BudgetExceededError:
            logger.warning("Retest %s exceeded budget", self.scan_id)
        except Exception as e:
            logger.exception("Retest %s failed: %s", self.scan_id, e)

        duration = round(time.time() - start_time, 1)
        return {
            "findings": self.findings,
            "cost": self.cost.to_dict(),
            "duration_seconds": duration,
            "messages": messages[-20:],
        }

    async def _tool_use_loop(
        self,
        system_prompt: str,
        messages: list[dict],
        max_iterations: int = MAX_TOOL_LOOP_ITERATIONS,
    ) -> list[dict]:
        """Core tool_use loop: send messages, handle tool calls, return updated messages."""
        import asyncio

        iteration = 0
        while iteration < max_iterations:
            iteration += 1

            # Budget check
            if self.cost.is_budget_exceeded():
                raise BudgetExceededError(f"Budget exceeded: ${self.cost.total_cost_usd:.2f} / ${self.cost.max_cost_usd:.2f}")

            # Select model based on current phase and budget
            model = self.cost.get_model_for_phase(self.cost.current_phase)
            if self.cost.should_downgrade_model():
                model = self.cost.get_downgraded_model(model)
                logger.info("Budget pressure: downgraded to %s", model)

            # Call Claude API
            try:
                response = await asyncio.to_thread(
                    self._call_claude_api,
                    system_prompt=system_prompt,
                    messages=messages,
                    model=model,
                )
            except Exception as e:
                error_msg = str(e)
                if "rate_limit" in error_msg.lower() or "429" in error_msg:
                    await self._handle_rate_limit(iteration)
                    continue
                raise

            # Record usage
            usage = response.usage
            self.cost.record_usage(
                model=model,
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cached_input_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            )

            # Process response content blocks
            assistant_content = []
            tool_results = []
            has_tool_use = False

            for block in response.content:
                if block.type == "text":
                    assistant_content.append({"type": "text", "text": block.text})
                    # Log Claude's reasoning to activity log
                    text_preview = block.text[:200] if block.text else ""
                    if text_preview:
                        self.activity_log.append({
                            "ts": time.time(),
                            "msg": text_preview,
                            "type": "reasoning",
                        })
                elif block.type == "tool_use":
                    has_tool_use = True
                    assistant_content.append({
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    })

                    # Execute tool
                    tool_result = await self._execute_tool(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": tool_result,
                    })

            # Add assistant message
            messages.append({"role": "assistant", "content": assistant_content})

            # If no tool use, Claude is done
            if not has_tool_use or response.stop_reason == "end_turn":
                break

            # Add tool results
            messages.append({"role": "user", "content": tool_results})

        return messages

    def _call_claude_api(self, system_prompt: str, messages: list[dict], model: str):
        """Synchronous Claude API call (run in thread)."""
        # Use prompt caching for system prompt
        response = self.client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=[{
                "type": "text",
                "text": system_prompt,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=messages,
            tools=self.tools,
        )
        return response

    async def _execute_tool(self, tool_name: str, tool_input: dict) -> str:
        """Execute a tool call and return result string."""
        import asyncio

        if not self._executor:
            return json.dumps({"error": "Tool executor not configured"})

        self._emit_progress(
            self.cost.current_phase,
            f"Executing: {tool_name}",
            current_tool=tool_name,
            log_type="tool",
        )

        try:
            result = await asyncio.to_thread(self._executor.execute, tool_name, tool_input)

            # Handle special tool results that update agent state
            if tool_name == "create_finding" and isinstance(result, dict):
                self.findings.append(result.get("finding", tool_input))
            elif tool_name == "save_crawl_result" and isinstance(result, dict):
                self.crawl_results.append(tool_input)
            elif tool_name == "save_test_case" and isinstance(result, dict):
                self.new_test_cases.append(tool_input)
            elif tool_name == "offer_pentest_option" and isinstance(result, dict):
                self.pentest_options.append(tool_input)
            elif tool_name == "update_progress":
                phase = tool_input.get("phase", self.cost.current_phase)
                self.cost.set_phase(phase)
                self._emit_progress(phase, tool_input.get("message", ""))

            return json.dumps(result, default=str) if isinstance(result, dict) else str(result)
        except Exception as e:
            logger.warning("Tool %s failed: %s", tool_name, e)
            return json.dumps({"error": str(e)[:500], "tool": tool_name})

    async def _handle_rate_limit(self, iteration: int) -> None:
        """Handle API rate limits with exponential backoff."""
        import asyncio
        delay = min(2 ** min(iteration, 6), 60)
        logger.warning("Rate limited, waiting %ds (iteration %d)", delay, iteration)
        self._emit_progress(
            self.cost.current_phase,
            f"Rate limited by API. Waiting {delay}s before retry... (attempt {iteration})",
            log_type="rate_limit",
            rate_limit_wait=delay,
        )
        await asyncio.sleep(delay)

    @staticmethod
    def _format_existing_findings(findings: list[dict]) -> str:
        """Format existing findings for the system prompt."""
        if not findings:
            return "None"
        lines = []
        for f in findings[:20]:
            lines.append(f"- [{f.get('severity', '?')}] {f.get('title', '?')} @ {f.get('affected_url', '?')}")
        if len(findings) > 20:
            lines.append(f"... and {len(findings) - 20} more")
        return "\n".join(lines)

    @staticmethod
    def _format_false_positives(findings: list[dict]) -> str:
        """Extract known false positives from findings."""
        fps = [f for f in findings if f.get("status") == "fp"]
        if not fps:
            return "None"
        return "\n".join(f"- {f.get('title', '?')}" for f in fps[:10])


class BudgetExceededError(Exception):
    """Raised when scan budget is exceeded."""
    pass
