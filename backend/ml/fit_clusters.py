"""Fit the behavioural cluster model on captured sessions.

Section VI.B claims the system "performs behavioural clustering for attacker
profiling". The rule-based scorecard it actually had is kept — it is
interpretable and works from the first session — but clustering is now real,
and this is what fits it.

Unlike the classifier, this needs no external dataset: it trains on the
honeypot's own captured sessions, which is the right corpus for grouping
behaviour and avoids the CIC-IDS2017 domain shift entirely.

    python -m ml.fit_clusters

Until it is run, the API reports ``behavioural_cluster: {"fitted": false}``
rather than inventing a cluster for every session.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

import numpy as np
from sqlalchemy import select

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ai.clustering import MIN_SESSIONS_TO_FIT, clusterer, extract  # noqa: E402
from app.core.database import async_session_factory  # noqa: E402
from app.core.encryption import decrypt_data  # noqa: E402
from app.models import HoneypotSession  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


async def main() -> int:
    async with async_session_factory() as db:
        sessions = (await db.execute(select(HoneypotSession))).scalars().all()

    if len(sessions) < MIN_SESSIONS_TO_FIT:
        print(
            f"Only {len(sessions)} session(s) captured; {MIN_SESSIONS_TO_FIT} "
            f"are needed.\nRun the honeypot engine first — fitting on fewer "
            f"would produce assignments that look like findings but are noise."
        )
        return 1

    vectors = []
    for s in sessions:
        commands = []
        if s.raw_commands_encrypted:
            try:
                commands = decrypt_data(s.raw_commands_encrypted).splitlines()
            except ValueError:
                pass
        vectors.append(extract(
            {
                "duration_seconds": s.duration_seconds,
                "commands": commands,
                "uploaded_files": s.uploaded_files or [],
            },
            {
                "tool_names": s.detected_tools or [],
                "detected_intents": s.detected_intents or [],
                "complexity_score": 0.0,
            },
        ))

    stats = clusterer.fit(np.vstack(vectors))
    print(f"\n  Fitted {stats['n_clusters']} clusters over {stats['n_sessions']} sessions")
    for cluster, size in sorted(stats["sizes"].items()):
        print(f"    cluster {cluster}: {size:,} session(s)")
    print(f"  inertia {stats['inertia']:.2f}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
