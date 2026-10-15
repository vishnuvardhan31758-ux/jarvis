"""jarvis/web/agent.py — Multi-Session Web Agent, XHR JSON API Discoverer & Download Quarantine."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from jarvis.contracts import (
    DataClass,
    EpistemicLabel,
    EvidenceRecord,
    PolicyDeniedError,
    PolicyEngineProtocol,
    PolicyRequest,
    RiskTier,
    StoreProtocol,
    TaskRecord,
)
from jarvis.web.security import SSRFGuard

EXEC_EXTENSIONS = (".exe", ".bat", ".cmd", ".sh", ".ps1", ".msi", ".dmg", ".scr", ".pkg")


class ApiDiscoverer:
    def __init__(self) -> None:
        self._endpoints: List[Dict[str, Any]] = []

    def record_response(self, url: str, content_type: str, status: int, body: str) -> None:
        if status == 200 and "json" in content_type.lower():
            try:
                data = json.loads(body)
            except Exception:
                return
            keys: List[str] = []
            count = 1
            if isinstance(data, list):
                count = len(data)
                if data and isinstance(data[0], dict):
                    keys = list(data[0].keys())
            elif isinstance(data, dict):
                keys = list(data.keys())
            self._endpoints.append({"url": url, "item_count": count, "keys": keys, "data": data})

    def discover_json_endpoints(self) -> List[Dict[str, Any]]:
        return list(self._endpoints)


class WebAgent:
    def __init__(
        self,
        store: StoreProtocol,
        policy: PolicyEngineProtocol,
        max_sessions: int = 4,
        quarantine_dir: str | Path = "data/quarantine",
    ) -> None:
        self.store = store
        self.policy = policy
        self.max_sessions = max_sessions
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.ssrf = SSRFGuard()
        self.api_discoverer = ApiDiscoverer()
        self._mock_pages: Dict[str, str] = {}

    def register_mock_page(
        self,
        url: str,
        html: str,
        xhr_payloads: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self._mock_pages[url] = html
        for xhr in xhr_payloads or []:
            self.api_discoverer.record_response(
                url=xhr.get("url", url + "/api"),
                content_type=xhr.get("content_type", "application/json"),
                status=int(xhr.get("status", 200)),
                body=xhr["body"] if isinstance(xhr["body"], str) else json.dumps(xhr["body"]),
            )

    def browse_and_extract(
        self,
        task: TaskRecord,
        url: str,
        selector: str = "body",
    ) -> Tuple[str, EvidenceRecord]:
        self.ssrf.validate_url(url, resolve_dns=(url not in self._mock_pages))
        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action="web.navigate",
            args={"url": url, "selector": selector},
            data_class=task.data_class,
            requested_risk=RiskTier.R0_READ_ONLY,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
        )
        dec = self.policy.evaluate(req)
        if not dec.allowed:
            raise PolicyDeniedError(dec.explanation)

        html = self._mock_pages.get(url, f"<html><body>Content from {url}</body></html>")
        text = re.sub(r"<script[\s\S]*?</script>", "", html, flags=re.IGNORECASE)
        text = re.sub(r"<style[\s\S]*?</style>", "", text, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", text)
        text = " ".join(text.split())

        wrapped = self.policy.wrap_untrusted(text, source=url)
        art = self.store.put_artifact(
            html.encode("utf-8"),
            media_type="text/html",
            data_class=DataClass.D0_PUBLIC,
            task_id=task.task_id,
        )
        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="web_source",
            content_summary=f"Fetched {url} ({len(text)} chars)",
            artifact_id=art.artifact_id,
            sha256=art.sha256,
            epistemic_label=EpistemicLabel.SOURCE_SUPPORTED,
        )
        self.store.save_evidence(ev)
        return wrapped, ev

    def submit_form(
        self,
        task: TaskRecord,
        url: str,
        form_data: Dict[str, Any],
        is_purchase: bool = False,
    ) -> Tuple[Dict[str, Any], EvidenceRecord]:
        self.ssrf.validate_url(url, resolve_dns=(url not in self._mock_pages))
        action = "finance.pay" if is_purchase else "web.submit"
        risk = RiskTier.R4_CRITICAL_IRREVERSIBLE if is_purchase else RiskTier.R2_EXTERNAL_REVERSIBLE
        host = urllib.parse.urlparse(url).hostname or ""
        req = PolicyRequest(
            task_id=task.task_id,
            domain=task.domain,
            action=action,
            args={"url": url, "domain": host, **form_data},
            data_class=task.data_class,
            requested_risk=risk,
            autonomy_level=task.autonomy_level,
            mandate_id=task.mandate_id,
        )
        dec = self.policy.evaluate(req)
        if not dec.allowed:
            raise PolicyDeniedError(dec.explanation)

        ev = EvidenceRecord(
            task_id=task.task_id,
            source_type="web_source",
            content_summary=f"Submitted form to {url}",
            sha256=hashlib.sha256(json.dumps(form_data, sort_keys=True).encode()).hexdigest(),
        )
        self.store.save_evidence(ev)
        return {"submitted": True, "url": url}, ev

    def quarantine_download(
        self,
        task: TaskRecord,
        url: str,
        content: bytes,
        filename: str,
    ) -> Dict[str, Any]:
        self.ssrf.validate_url(url, resolve_dns=(url not in self._mock_pages))
        sha = hashlib.sha256(content).hexdigest()
        safe_name = Path(filename).name
        target = self.quarantine_dir / f"{sha[:12]}_{safe_name}"
        target.write_bytes(content)
        flagged = safe_name.lower().endswith(EXEC_EXTENSIONS)
        return {
            "quarantine_path": str(target),
            "sha256": sha,
            "size_bytes": len(content),
            "flagged_executable": flagged,
        }
