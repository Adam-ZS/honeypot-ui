"""Chimera client — semantic analysis of attacker command transcripts.

Finding 12: the report calls this a "SpaCy-based NLP engine" performing
"semantic intent analysis", and §XI claims it parses payloads "beyond keyword
matching". What shipped was twenty regexes and ten substring lists; spaCy only
ever did named-entity extraction, and degraded to nothing when the model was
absent. The claim described a capability the code did not have.

This adds the capability rather than softening the claim, using the project's
own fine-tune (``mandoof1/chimera-14b-v2``, a QLoRA adapter over Ministral-3
14B trained on MITRE ATT&CK and defensive-security data).

Three constraints shaped the design:

*It must not sit in the ingest path.* NFR-2 budgets 200 ms for classification.
A 14B model at Q4_K_M answers in seconds to tens of seconds. So this runs as
stage 2, asynchronously, after the Random Forest has already returned a verdict
and the session is stored.

*It must not create an egress path from the honeypot.* NFR-1 requires zero
egress from the engine. The model is called from the **backend**, never from
the engine, and it is the user's own weights served locally — not a third-party
API, which would make the isolation claim false.

*It must degrade to nothing.* If no endpoint is configured or the model is
unreachable, analysis falls back to the regex path and ingest is unaffected.
A honeypot that stops recording because an inference server is down has traded
its actual job for an enrichment.

Talks the OpenAI-compatible chat API that llama.cpp's server, Ollama and vLLM
all expose, so the weights can run anywhere — a laptop, a Colab GPU, a
workstation — and only ``CHIMERA_URL`` changes.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

#: Transcripts are attacker-controlled; cap what is sent for inference.
MAX_TRANSCRIPT_CHARS = 6000

SYSTEM_PROMPT = """\
You are a blue-team analyst reviewing commands captured by a honeypot. The \
session is already contained: nothing you are shown was executed on a real \
system, and your job is to describe what the attacker was attempting.

Answer with a single JSON object and nothing else:

{
  "intent": "<one sentence on what the attacker was trying to achieve>",
  "objectives": ["<short phrases, at most 5>"],
  "mitre_techniques": [{"id": "T1059.004", "name": "Unix Shell"}],
  "iocs": {"hosts": [], "urls": [], "files": []},
  "sophistication": "automated|script_kiddie|skilled|apt",
  "confidence": 0.0
}

Only list ATT&CK techniques the commands actually evidence. An empty list is \
a valid and useful answer; do not pad it. Keep every string short."""


class ChimeraClient:
    """Optional semantic-analysis stage. Absent by default."""

    def __init__(self) -> None:
        self._settings = get_settings()

    @property
    def enabled(self) -> bool:
        return bool(self._settings.CHIMERA_URL)

    async def analyse(self, commands: list[str], protocol: str = "ssh") -> Optional[dict]:
        """Return the model's reading of a transcript, or None.

        None means "no analysis available" — never an exception into the
        caller. Every failure here is non-fatal by construction.
        """
        if not self.enabled or not commands:
            return None

        transcript = "\n".join(commands)[:MAX_TRANSCRIPT_CHARS]
        payload = {
            "model": self._settings.CHIMERA_MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Protocol: {protocol}\n"
                        f"Commands captured, in order:\n\n{transcript}"
                    ),
                },
            ],
            # Low but not zero: the adapter is a reasoning model, and greedy
            # decoding on these makes it repeat itself on long transcripts.
            "temperature": 0.2,
            "max_tokens": 700,
            "stream": False,
        }

        url = self._settings.CHIMERA_URL.rstrip("/") + "/chat/completions"
        try:
            async with httpx.AsyncClient(timeout=self._settings.CHIMERA_TIMEOUT) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                body = response.json()
        except httpx.TimeoutException:
            logger.warning("Chimera timed out after %ss; skipping enrichment",
                           self._settings.CHIMERA_TIMEOUT)
            return None
        except Exception as exc:
            logger.warning("Chimera unavailable (%s); skipping enrichment", exc)
            return None

        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            logger.warning("Chimera returned an unexpected response shape")
            return None

        parsed = self._parse(content)
        if parsed is None:
            return None
        parsed["model_source"] = self._settings.CHIMERA_MODEL
        return parsed

    @staticmethod
    def _parse(content: str) -> Optional[dict]:
        """Pull the JSON object out of a reasoning model's reply.

        Reasoning fine-tunes narrate before answering however firmly the
        prompt asks them not to, so the object is extracted rather than
        assumed to be the whole response.
        """
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content)

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if not match:
                return None
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                logger.warning("Chimera reply contained no parseable JSON")
                return None

        if not isinstance(data, dict):
            return None

        # Normalise defensively: this is model output, so nothing about the
        # shape is guaranteed even when the JSON parses.
        techniques = []
        for item in (data.get("mitre_techniques") or [])[:20]:
            if isinstance(item, dict) and item.get("id"):
                tid = str(item["id"]).strip().upper()
                # Reject anything that is not shaped like a technique ID —
                # a hallucinated label must not enter the ATT&CK mapping.
                if re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid):
                    techniques.append({"id": tid, "name": str(item.get("name", ""))[:120]})

        iocs = data.get("iocs") if isinstance(data.get("iocs"), dict) else {}
        return {
            "intent": str(data.get("intent", ""))[:500],
            "objectives": [str(o)[:80] for o in (data.get("objectives") or [])[:5]],
            "mitre_techniques": techniques,
            "iocs": {
                "hosts": [str(h)[:120] for h in (iocs.get("hosts") or [])[:20]],
                "urls": [str(u)[:300] for u in (iocs.get("urls") or [])[:20]],
                "files": [str(f)[:200] for f in (iocs.get("files") or [])[:20]],
            },
            "sophistication": str(data.get("sophistication", "unknown"))[:32],
            "confidence": _clamp_confidence(data.get("confidence")),
        }


def _clamp_confidence(value) -> Optional[float]:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return None


chimera = ChimeraClient()
