"""Stage 2: semantic enrichment, out of the ingest path.

The analysis pipeline is deliberately two-stage.

Stage 1 is synchronous and fast: the Random Forest classifies session features
and the session is written. That path owns NFR-2's 200 ms budget, and it is
what the API returns.

Stage 2 is this. It reads the stored command transcript, asks Chimera what the
attacker was attempting, and merges the answer back onto the session. It runs
as a background task after the response has already gone out, because a 14B
model answers in seconds and putting it inline would blow the latency budget
by two orders of magnitude.

The split means a slow or absent model degrades the *depth* of analysis and
never the *capture*. A honeypot that stops recording because an inference
server is down has traded its actual job for an enrichment.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.llm import chimera
from app.core.database import async_session_factory
from app.core.encryption import decrypt_data
from app.models import HoneypotSession, IndicatorOfCompromise

logger = logging.getLogger(__name__)

#: Cap on concurrent inference. One local model serves one request at a time in
#: practice; without this a burst of sessions queues unbounded work against it.
_semaphore = asyncio.Semaphore(2)


def schedule(session_id: int) -> None:
    """Queue enrichment for a stored session, if the model is configured.

    Fire-and-forget on purpose: the caller has already responded to the
    honeypot engine, and nothing downstream waits on this.
    """
    if not chimera.enabled:
        return
    task = asyncio.create_task(_enrich(session_id))
    # Hold a reference so the task is not garbage-collected mid-flight, which
    # asyncio does not prevent on its own.
    _pending.add(task)
    task.add_done_callback(_pending.discard)


_pending: set[asyncio.Task] = set()


async def _enrich(session_id: int) -> None:
    try:
        async with _semaphore:
            async with async_session_factory() as db:
                await _run(db, session_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        # Never propagate: this runs detached, and a failure here must not
        # affect anything the pipeline already committed.
        logger.warning("Enrichment failed for session %s: %s", session_id, exc)


async def _run(db: AsyncSession, session_id: int) -> None:
    session = (
        await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    ).scalar_one_or_none()
    if session is None:
        return

    commands = _decrypt_commands(session)
    if not commands:
        return

    analysis = await chimera.analyse(commands, protocol=session.protocol or "ssh")
    if analysis is None:
        return

    _merge_techniques(session, analysis)
    _merge_intents(session, analysis)
    db.add_all(_new_iocs(session, analysis))

    await db.commit()
    logger.info(
        "Enriched session %s: %d technique(s), %d objective(s)",
        session_id,
        len(analysis["mitre_techniques"]),
        len(analysis["objectives"]),
    )


def _decrypt_commands(session: HoneypotSession) -> list[str]:
    if not session.raw_commands_encrypted:
        return []
    try:
        raw = decrypt_data(session.raw_commands_encrypted)
    except ValueError:
        logger.warning("Could not decrypt commands for session %s", session.id)
        return []
    return [line for line in raw.splitlines() if line.strip()]


def _merge_techniques(session: HoneypotSession, analysis: dict) -> None:
    """Add techniques the rule-based mapper missed, without displacing it.

    The static map in mitre_mapper.py is precise but can only report what a
    regex already matched. The model generalises to command sequences the
    dictionary has never seen. Union rather than replace: a hallucinated
    technique should not be able to remove a matched one.
    """
    existing = list(session.mitre_techniques or [])
    known = {t.get("id") for t in existing if isinstance(t, dict)}

    for technique in analysis["mitre_techniques"]:
        if technique["id"] not in known:
            existing.append({**technique, "source": "chimera"})
            known.add(technique["id"])

    session.mitre_techniques = existing


def _merge_intents(session: HoneypotSession, analysis: dict) -> None:
    intents = list(session.detected_intents or [])
    for objective in analysis["objectives"]:
        normalised = objective.strip().lower().replace(" ", "_")[:64]
        if normalised and normalised not in intents:
            intents.append(normalised)
    session.detected_intents = intents

    if analysis["intent"]:
        # Prepend rather than overwrite: command_summary may already hold the
        # rule-based summary, and the model's reading is an addition to it.
        prefix = f"[chimera] {analysis['intent']}"
        session.command_summary = (
            prefix if not session.command_summary
            else f"{prefix}\n{session.command_summary}"
        )[:4000]


def _new_iocs(session: HoneypotSession, analysis: dict) -> list[IndicatorOfCompromise]:
    """Record hosts, URLs and files the model recovered as indicators."""
    rows: list[IndicatorOfCompromise] = []
    for ioc_type, values in (
        ("host", analysis["iocs"]["hosts"]),
        ("url", analysis["iocs"]["urls"]),
        ("file", analysis["iocs"]["files"]),
    ):
        for value in values:
            if value.strip():
                rows.append(
                    IndicatorOfCompromise(
                        session_id=session.id,
                        ioc_type=ioc_type,
                        value=value.strip()[:500],
                        confidence=analysis["confidence"],
                        tags=["chimera"],
                    )
                )
    return rows
