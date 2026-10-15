"""jarvis/research/agent.py — Cited Research Agent with Claim-Source Fidelity & Contradiction Detection."""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from jarvis.contracts import (
    CitedClaim,
    DataClass,
    EpistemicLabel,
    EvidenceRecord,
    PolicyEngineProtocol,
    StoreProtocol,
    TaskRecord,
    WebResearchProtocol,
)
from jarvis.web.agent import WebAgent
from jarvis.web.monitor import PageMonitor
from jarvis.web.security import SSRFGuard


class WebResearchService:
    def __init__(self, store: StoreProtocol, policy: PolicyEngineProtocol) -> None:
        self.store = store
        self.policy = policy
        self.ssrf = SSRFGuard()
        self.web_agent = WebAgent(store=store, policy=policy)
        self.monitor = PageMonitor()

    def validate_url(self, url: str) -> str:
        return self.ssrf.validate_url(url)

    def browse_and_extract(self, task: TaskRecord, url: str, selector: str = "body") -> Tuple[str, EvidenceRecord]:
        return self.web_agent.browse_and_extract(task=task, url=url, selector=selector)

    def conduct_research(
        self,
        task: TaskRecord,
        query: str,
        sources: List[Dict[str, str]],
    ) -> List[CitedClaim]:
        claims: List[CitedClaim] = []
        verified_numeric_sources: List[Tuple[str, str, List[str], str]] = []

        for src in sources:
            url = src.get("url", "https://example.com")
            text = src.get("text", "")
            quote = src.get("quote_span", text)
            claim_stmt = src.get("claim", quote)
            src_date = src.get("date")

            art = self.store.put_artifact(
                text.encode("utf-8"),
                media_type="text/plain",
                data_class=DataClass.D0_PUBLIC,
                task_id=task.task_id,
            )
            ev = EvidenceRecord(
                task_id=task.task_id,
                source_type="web_source",
                content_summary=f"Research source {url}",
                artifact_id=art.artifact_id,
                sha256=art.sha256,
                epistemic_label=EpistemicLabel.SOURCE_SUPPORTED,
            )
            self.store.save_evidence(ev)

            norm_text = " ".join(text.lower().split())
            norm_quote = " ".join(quote.lower().split())
            if norm_quote and norm_quote in norm_text:
                label = EpistemicLabel.SOURCE_SUPPORTED
                nums = re.findall(r"\b\d+(?:\.\d+)?%?\b", quote)
                if nums:
                    verified_numeric_sources.append((art.artifact_id, url, nums, quote))
            else:
                label = EpistemicLabel.UNVERIFIED

            claims.append(
                CitedClaim(
                    statement=claim_stmt,
                    epistemic_label=label,
                    source_artifact_ids=[art.artifact_id],
                    source_urls=[url],
                    quote_span=quote,
                    source_date=src_date,
                )
            )

        if len(verified_numeric_sources) >= 2:
            first_nums = set(verified_numeric_sources[0][2])
            for other in verified_numeric_sources[1:]:
                if set(other[2]) != first_nums:
                    claims.append(
                        CitedClaim(
                            statement=(
                                f"Disputed figures for '{query}': {verified_numeric_sources[0][1]} reports "
                                f"{verified_numeric_sources[0][2]} while {other[1]} reports {other[2]}"
                            ),
                            epistemic_label=EpistemicLabel.DISPUTED,
                            source_artifact_ids=[verified_numeric_sources[0][0], other[0]],
                            source_urls=[verified_numeric_sources[0][1], other[1]],
                            quote_span=f"{verified_numeric_sources[0][3]} || {other[3]}",
                        )
                    )
                    break

        return claims
