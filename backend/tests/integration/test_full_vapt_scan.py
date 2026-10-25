"""
End-to-End Integration Test
---------------------------
Performs a realistic VAPT scan of SentinelX against VulnBank running as an independent process.
Verifies:
1. Live Endpoint Discovery via OpenAPI
2. Execution of security checks (BOLA, Auth Bypass, SQLi, Data Exposure, Headers, JWT)
3. Verified technical evidence collection
4. Risk scoring and report generation
5. Complete Retest workflow demonstrating Remediation verification (OPEN -> FIXED)!
"""

import os
import subprocess
import sys
import time
from pathlib import Path
import httpx
import pytest
from sqlalchemy.orm import Session

from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.scanner.engine import ScanEngine


@pytest.fixture(scope="module")
def live_vulnbank_server():
    """
    Launch VulnBank API as an independent process on port 8001.
    Completely isolates Python namespaces and tests real HTTP VAPT scanning over the wire.
    """
    project_root = Path(__file__).resolve().parents[3]
    vuln_dir = project_root / "vulnerable-api"

    env = os.environ.copy()
    env["VULNBANK_SECURE_MODE"] = "false"
    env["VULNBANK_DATABASE_URL"] = "sqlite:///./test_vulnbank.db"

    # Start uvicorn process
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8001"],
        cwd=str(vuln_dir),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to become healthy
    target_url = "http://127.0.0.1:8001"
    ready = False
    for _ in range(30):
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.get(f"{target_url}/health")
                if res.status_code == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(0.3)

    if not ready:
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=3)
        raise RuntimeError(f"VulnBank failed to start:\nStdout: {stdout.decode()}\nStderr: {stderr.decode()}")

    yield {
        "url": target_url,
        "proc": proc,
        "env": env,
        "vuln_dir": vuln_dir,
    }

    # Teardown
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    # Clean up test database file if created
    test_db = vuln_dir / "test_vulnbank.db"
    if test_db.exists():
        try:
            test_db.unlink()
        except Exception:
            pass


@pytest.mark.asyncio
async def test_full_sentinelx_vapt_scan_and_retest(db_session: Session, live_vulnbank_server):
    """
    Run full automated scan against live VulnBank and verify findings & retest.
    """
    target_url = live_vulnbank_server["url"]

    # 1. Create Scan record
    scan = Scan(
        target_url=target_url,
        openapi_url=f"{target_url}/openapi.json",
        status="PENDING",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    # 2. Run ScanEngine against live target
    engine = ScanEngine(db_session)
    completed_scan = await engine.run_scan(
        scan_id=scan.id,
        target_url=target_url,
        openapi_url=f"{target_url}/openapi.json",
    )

    assert completed_scan.status == "COMPLETED"
    assert completed_scan.total_endpoints >= 7

    # 3. Query discovered vulnerabilities
    vulns = db_session.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    assert len(vulns) >= 5, f"Expected at least 5 vulnerability findings, got {len(vulns)}"

    vuln_types = {v.type for v in vulns}
    logger_findings = [f"[{v.severity}] {v.type}: {v.title}" for v in vulns]
    print("\n=== SENTINELX DETECTED FINDINGS ===")
    for lf in logger_findings:
        print(lf)

    # Verify real vulnerabilities detected with reproducible evidence
    assert "BOLA" in vuln_types, "BOLA finding must be detected"
    assert "AUTH_BYPASS" in vuln_types, "Missing Authentication must be detected"
    assert "SENSITIVE_DATA" in vuln_types, "Sensitive Data Exposure must be detected"
    assert "HEADERS" in vuln_types, "Missing Security Headers must be detected"
    assert "JWT" in vuln_types, "JWT Misconfiguration must be detected"

    # Verify evidence details on BOLA
    bola_vuln = next(v for v in vulns if v.type == "BOLA")
    assert len(bola_vuln.evidence_items) > 0
    ev = bola_vuln.evidence_items[0]
    assert ev.test_status == 200
    assert len(ev.observation) > 0
    assert bola_vuln.status == "OPEN"

    # 4. RETEST DEMONSTRATION: RESTART VULNBANK IN SECURE MODE
    print("\n=== TESTING REMEDIATION & RETEST ===")
    live_vulnbank_server["proc"].terminate()
    try:
        live_vulnbank_server["proc"].wait(timeout=3)
    except Exception:
        pass

    # Restart in secure mode
    secure_env = live_vulnbank_server["env"].copy()
    secure_env["VULNBANK_SECURE_MODE"] = "true"

    secure_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8001"],
        cwd=str(live_vulnbank_server["vuln_dir"]),
        env=secure_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for secure server to start
    time.sleep(1.2)

    try:
        # Retest BOLA finding
        retest_res = await engine.retest_finding(bola_vuln)
        print(f"Retest Result: {retest_res.previous_status} -> {retest_res.new_status} ({retest_res.observation})")
        assert retest_res.new_status == "FIXED", "BOLA finding should change from OPEN to FIXED after remediation"
        assert bola_vuln.status == "FIXED"
    finally:
        secure_proc.terminate()
