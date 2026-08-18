import asyncio
import logging
import random
from datetime import datetime, timezone, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select

from app.core.database import async_session_factory, init_db
from app.models import (
    User, HoneypotNode, HoneypotSession, Alert, IndicatorOfCompromise,
    AlertThreshold, UserRole, HoneypotMode, SessionStatus,
    AttackCategory, AttackSeverity, AttackerProfile, AlertStatus,
)
from app.core.security import get_password_hash

logger = logging.getLogger(__name__)

#: Number of synthetic sessions the demo dataset contains.
SESSION_COUNT = 150

ATTACKER_IPS = [
    ("185.220.101.47", "RU", "Russia", "Moscow", 55.7558, 37.6173),
    ("45.142.212.100", "CN", "China", "Beijing", 39.9042, 116.4074),
    ("91.108.4.33", "DE", "Germany", "Berlin", 52.5200, 13.4050),
    ("198.11.222.9", "US", "United States", "New York", 40.7128, -74.0060),
    ("23.95.4.12", "NL", "Netherlands", "Amsterdam", 52.3676, 4.9041),
    ("103.75.190.4", "IN", "India", "Mumbai", 19.0760, 72.8777),
    ("62.210.16.27", "FR", "France", "Paris", 48.8566, 2.3522),
    ("176.31.74.183", "UA", "Ukraine", "Kyiv", 50.4501, 30.5234),
    ("218.92.0.107", "CN", "China", "Shanghai", 31.2304, 121.4737),
    ("77.247.181.163", "NL", "Netherlands", "Rotterdam", 51.9244, 4.4777),
    ("185.56.80.65", "RU", "Russia", "St. Petersburg", 59.9343, 30.3351),
    ("142.44.191.76", "CA", "Canada", "Toronto", 43.6532, -79.3832),
    ("51.15.43.205", "FR", "France", "Lyon", 45.7640, 4.8357),
    ("89.248.167.131", "NL", "Netherlands", "The Hague", 52.0705, 4.3007),
    ("195.54.160.149", "DE", "Germany", "Munich", 48.1351, 11.5820),
    ("116.105.71.203", "VN", "Vietnam", "Hanoi", 21.0278, 105.8342),
    ("200.54.138.22", "BR", "Brazil", "Sao Paulo", -23.5505, -46.6333),
    ("212.70.149.82", "GB", "United Kingdom", "London", 51.5074, -0.1278),
    ("104.248.89.77", "US", "United States", "San Francisco", 37.7749, -122.4194),
    ("159.65.140.101", "SG", "Singapore", "Singapore", 1.3521, 103.8198),
]

ATTACK_TYPES = [
    ("SSH Brute Force", AttackCategory.EXPLOITATION, ["hydra", "medusa"], ["credential_harvesting"]),
    ("SQL Injection", AttackCategory.EXPLOITATION, ["sqlmap", "burpsuite"], ["privilege_escalation"]),
    ("Port Scan (SYN)", AttackCategory.RECONNAISSANCE, ["nmap", "masscan"], ["reconnaissance"]),
    ("RDP Exploitation", AttackCategory.EXPLOITATION, ["metasploit"], ["privilege_escalation", "lateral_movement"]),
    ("XSS Attempt", AttackCategory.EXPLOITATION, ["burpsuite"], ["exploitation"]),
    ("Command Injection", AttackCategory.EXPLOITATION, ["netcat", "metasploit"], ["privilege_escalation"]),
    ("Directory Traversal", AttackCategory.RECONNAISSANCE, ["gobuster", "nikto"], ["reconnaissance"]),
    ("Malware Beacon", AttackCategory.EXFILTRATION, ["cobalt_strike", "empire"], ["persistence", "data_exfiltration"]),
    ("FTP Brute Force", AttackCategory.EXPLOITATION, ["hydra"], ["credential_harvesting"]),
    ("HTTP Scanner", AttackCategory.RECONNAISSANCE, ["nikto", "nmap"], ["reconnaissance"]),
    ("Reverse Shell Attempt", AttackCategory.EXPLOITATION, ["netcat", "metasploit"], ["reverse_shell"]),
    ("Data Exfiltration", AttackCategory.EXFILTRATION, ["wget_curl", "netcat"], ["data_exfiltration"]),
]

TOOLS_DB = {
    "hydra": {"category": "password_cracker"},
    "medusa": {"category": "password_cracker"},
    "sqlmap": {"category": "sql_injection"},
    "burpsuite": {"category": "web_proxy"},
    "nmap": {"category": "scanner"},
    "masscan": {"category": "scanner"},
    "metasploit": {"category": "exploitation_framework"},
    "gobuster": {"category": "directory_enum"},
    "nikto": {"category": "vulnerability_scanner"},
    "cobalt_strike": {"category": "c2_framework"},
    "empire": {"category": "c2_framework"},
    "netcat": {"category": "network_utility"},
    "wget_curl": {"category": "file_download"},
}

MITRE_TECHNIQUES = {
    "SSH Brute Force": [{"id": "T1110.001", "name": "Password Guessing"}],
    "SQL Injection": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "Port Scan (SYN)": [{"id": "T1046", "name": "Network Service Discovery"}],
    "RDP Exploitation": [{"id": "T1190", "name": "Exploit Public-Facing Application"}, {"id": "T1021.001", "name": "Remote Desktop Protocol"}],
    "XSS Attempt": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
    "Command Injection": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
    "Directory Traversal": [{"id": "T1083", "name": "File and Directory Discovery"}],
    "Malware Beacon": [{"id": "T1071", "name": "Application Layer Protocol"}, {"id": "T1571", "name": "Non-Standard Port"}],
    "FTP Brute Force": [{"id": "T1110.001", "name": "Password Guessing"}],
    "HTTP Scanner": [{"id": "T1595", "name": "Active Scanning"}],
    "Reverse Shell Attempt": [{"id": "T1059", "name": "Command and Scripting Interpreter"}],
    "Data Exfiltration": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}],
}

MITRE_TACTICS = {
    AttackCategory.RECONNAISSANCE: ["TA0043"],
    AttackCategory.EXPLOITATION: ["TA0001", "TA0004"],
    AttackCategory.EXFILTRATION: ["TA0010", "TA0011"],
}


async def seed_database():
    from app.core.database import async_session_factory
    async with async_session_factory() as db:
        import os as _os

        seed_email = _os.environ.get("ADMIN_SEED_EMAIL", "admin@honeysentinel.io")
        existing = await db.execute(select(User).where(User.email == seed_email))
        if existing.scalar_one_or_none():
            logger.info("Database already seeded; nothing to do.")
            return

        import os
        import secrets

        admin_email = os.environ.get("ADMIN_SEED_EMAIL", "admin@honeysentinel.io")
        admin_pass = os.environ.get("ADMIN_SEED_PASSWORD")
        generated = admin_pass is None
        if generated:
            admin_pass = secrets.token_urlsafe(24)
            # Printed once, only because there is no other way to hand over a
            # generated credential. Set ADMIN_SEED_PASSWORD to avoid writing a
            # password to the application log at all.
            print(
                "\n" + "=" * 68
                + f"\n  SEED ADMIN: {admin_email}"
                + f"\n  PASSWORD  : {admin_pass}"
                + "\n  Change this immediately and set ADMIN_SEED_PASSWORD"
                + "\n  to suppress this output on future seeds."
                + "\n" + "=" * 68 + "\n",
                flush=True,
            )

        admin = User(
            email=admin_email,
            hashed_password=get_password_hash(admin_pass),
            name="Security Admin",
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True,
        )
        db.add(admin)
        await db.flush()

        # One node matching the name the engine registers itself under, so a
        # locally-running engine attaches to it instead of creating a second.
        # The Cowrie/Dionaea entries this used to create were fictional: no
        # such collectors exist in this project.
        nodes = [
            HoneypotNode(
                name=os.environ.get("HONEYPOT_NODE_NAME", "honeypot-engine-main"),
                protocol="multi",
                ip_address="0.0.0.0",
                port=2222,
                mode=HoneypotMode.ACTIVE,
            ),
        ]
        db.add_all(nodes)
        await db.flush()

        existing_threshold = await db.execute(select(AlertThreshold).where(AlertThreshold.name == "Default High Severity"))
        if not existing_threshold.scalar_one_or_none():
            threshold = AlertThreshold(
                name="Default High Severity",
                min_severity=AttackSeverity.MEDIUM,
                anomaly_score_threshold=0.7,
                email_enabled=True,
                webhook_enabled=False,
            )
            db.add(threshold)

        now = datetime.now(timezone.utc)
        sessions_data = []
        for i in range(SESSION_COUNT):
            ip_info = random.choice(ATTACKER_IPS)
            attack = random.choice(ATTACK_TYPES)
            node = random.choice(nodes)
            time_offset = timedelta(hours=random.randint(0, 72), minutes=random.randint(0, 59))
            started_at = now - time_offset
            duration = random.uniform(5, 600)

            category = attack[1]
            tools = attack[2]
            intents = attack[3]
            confidence = random.uniform(0.65, 0.99)

            profile_weights = {"script_kiddie": 0.4, "automated_bot": 0.35, "apt": 0.15, "unknown": 0.1}
            profile = random.choices(list(profile_weights.keys()), weights=list(profile_weights.values()))[0]

            anomaly_score = random.uniform(0.1, 0.95)
            is_anomalous = anomaly_score > 0.6

            mitre_techs = MITRE_TECHNIQUES.get(attack[0], [])
            mitre_tacs = MITRE_TACTICS.get(category, [])

            severity = AttackSeverity.LOW
            if category == AttackCategory.EXPLOITATION:
                severity = random.choice([AttackSeverity.HIGH, AttackSeverity.CRITICAL, AttackSeverity.MEDIUM])
            elif category == AttackCategory.EXFILTRATION:
                severity = AttackSeverity.CRITICAL
            elif category == AttackCategory.RECONNAISSANCE:
                severity = random.choice([AttackSeverity.LOW, AttackSeverity.MEDIUM])

            status = random.choice([SessionStatus.COMPLETED, SessionStatus.COMPLETED, SessionStatus.COMPLETED, SessionStatus.ACTIVE])

            session = HoneypotSession(
                attacker_ip=ip_info[0],
                attacker_port=random.randint(1024, 65535),
                node_id=node.id,
                geo_country=ip_info[1],
                geo_country_name=ip_info[2],
                geo_city=ip_info[3],
                geo_lat=ip_info[4] + random.uniform(-0.5, 0.5),
                geo_lon=ip_info[5] + random.uniform(-0.5, 0.5),
                status=status,
                started_at=started_at,
                ended_at=started_at + timedelta(seconds=duration) if status != SessionStatus.ACTIVE else None,
                duration_seconds=duration,
                attack_category=category,
                attack_confidence=confidence,
                attacker_profile=AttackerProfile(profile),
                anomaly_score=anomaly_score,
                is_anomalous=is_anomalous,
                detected_tools=tools,
                detected_intents=intents,
                command_summary=f"{attack[0]} from {ip_info[0]}",
                mitre_tactics=mitre_tacs,
                mitre_techniques=mitre_techs,
                uploaded_files=[f"payload_{random.randint(1000,9999)}.bin"] if random.random() > 0.7 else [],
            )
            db.add(session)
            sessions_data.append((session, ip_info, attack, severity))

        await db.flush()

        for session, ip_info, attack, severity in sessions_data:
            if severity in (AttackSeverity.HIGH, AttackSeverity.CRITICAL):
                alert = Alert(
                    session_id=session.id,
                    severity=severity,
                    title=f"{attack[0]} from {ip_info[0]}",
                    description=f"AI classified session as {session.attack_category.value} with {session.attack_confidence:.1%} confidence.",
                    status=random.choice([AlertStatus.NEW, AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED]),
                    mitre_tactics=session.mitre_tactics,
                    mitre_techniques=session.mitre_techniques,
                )
                db.add(alert)

            ioc = IndicatorOfCompromise(
                session_id=session.id,
                ioc_type="ip",
                value=ip_info[0],
                confidence=0.95,
                tags=["attacker_ip"],
            )
            db.add(ioc)

        await db.commit()
        # Report what was actually written. The previous message was a fixed
        # string claiming "3 users, 4 honeypot nodes" regardless of the truth.
        alert_count = (
            await db.execute(select(func.count(Alert.id)))
        ).scalar() or 0
        ioc_count = (
            await db.execute(select(func.count(IndicatorOfCompromise.id)))
        ).scalar() or 0
        logger.info(
            "Seeded demo dataset: %d user(s), %d node(s), %d session(s), "
            "%d alert(s), %d IoC(s)",
            1,
            len(nodes),
            len(sessions_data),
            alert_count,
            ioc_count,
        )


if __name__ == "__main__":
    asyncio.run(seed_database())
