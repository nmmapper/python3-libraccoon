import re
from typing import Dict, Any, List, Pattern
from .client import AsyncHTTPClient
from .fingerprints import WAF_FINGERPRINTS
from .probes import PROBES


class WAFDetector:
    """
    Async WAF detector with active probing and normalized confidence.
    """

    MAX_SCORE = 10  # used for normalization

    def __init__(self, url: str, enable_probing: bool = True) -> None:
        self.url = url.rstrip("/")
        self.enable_probing = enable_probing
        self._compiled = self._compile_fingerprints()

    @staticmethod
    def _compile_fingerprints() -> Dict[str, Dict[str, Any]]:
        compiled = {}

        for waf, rule in WAF_FINGERPRINTS.items():
            compiled[waf] = {
                "headers": [re.compile(p, re.I) for p in rule["headers"]],
                "body": [re.compile(p, re.I) for p in rule["body"]],
                "header_weight": rule["header_weight"],
                "body_weight": rule["body_weight"],
            }

        return compiled

    @staticmethod
    def _normalize_headers(headers: Dict[str, str]) -> str:
        return " ".join(
            f"{k.lower()}: {v.lower()}" for k, v in headers.items()
        )

    def _score_passive(self, headers: str, body: str) -> Dict[str, int]:
        scores: Dict[str, int] = {}

        for waf, rule in self._compiled.items():
            score = 0

            if any(r.search(headers) for r in rule["headers"]):
                score += rule["header_weight"]

            if any(r.search(body) for r in rule["body"]):
                score += rule["body_weight"]

            if score:
                scores[waf] = score

        return scores

    def _score_active(
        self, scores: Dict[str, int], headers: str, body: str
    ) -> None:
        """
        Active probing boosts confidence when block pages are detected.
        """
        for waf, rule in self._compiled.items():
            if waf not in scores:
                continue

            if any(r.search(headers) for r in rule["headers"]) or \
               any(r.search(body) for r in rule["body"]):
                scores[waf] += 2  # active block confirmation

    @staticmethod
    def _normalize_confidence(raw_score: int) -> int:
        """
        Convert raw score to 0–100 confidence.
        """
        return min(int((raw_score / WAFDetector.MAX_SCORE) * 100), 100)

    async def detect(self) -> Dict[str, Any]:
        async with AsyncHTTPClient() as client:
            base_response = await client.fetch(self.url)

            headers_text = self._normalize_headers(
                dict(base_response.headers)
            )
            body_text = base_response.text.lower()

            scores = self._score_passive(headers_text, body_text)

            # -------- ACTIVE PROBING --------
            if self.enable_probing and scores:
                for payload in PROBES:
                    try:
                        resp = await client.probe(self.url, payload)
                    except Exception:
                        continue

                    probe_headers = self._normalize_headers(
                        dict(resp.headers)
                    )
                    probe_body = resp.text.lower()

                    self._score_active(scores, probe_headers, probe_body)

        results = []
        for waf, score in scores.items():
            results.append(
                {
                    "waf": waf,
                    "raw_score": score,
                    "confidence": self._normalize_confidence(score),
                }
            )

        results.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "url": self.url,
            "status_code": base_response.status_code,
            "detected": bool(results),
            "results": results,
        }
