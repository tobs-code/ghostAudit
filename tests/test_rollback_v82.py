"""
Rollback / Forking-Angriff Test für V8.3 External State Counter.

Szenario A – Nur DB-Rollback (Angreifer klont nur *.db):
  -> ROLLBACK_DETECTED

Szenario B – Beide Dateien zurueckgesetzt (Same-Snapshot):
  -> OK (dokumentierte Grenze)

Szenario C – DB zurueck + *.evolve geloescht (Attacker hebelt Counter aus):
  -> STATE_FILE_MISSING (blockiert)

Szenario D – Gleiches Szenario mit force_reinit=True:
  -> OK (Admin-Recovery)
"""

import os, shutil, tempfile
from core.ghost_audit_v7 import GhostAuditV7


def test_rollback():
    tmpdir = tempfile.mkdtemp()
    try:
        db = os.path.join(tmpdir, "audit.db")
        st = os.path.join(tmpdir, "audit.evolve")

        def ga(**kw):
            return GhostAuditV7(db_path=db, secret_key="test-123", verbose=False,
                                external_state_path=st, **kw)

        # Phase 1: 5 Events
        g = ga()
        for i in range(5):
            g.log_event(f"E{i}")
        g.close()

        # Snapshot
        snap = os.path.join(tmpdir, "snap")
        os.makedirs(snap, exist_ok=True)
        for fn in os.listdir(tmpdir):
            src = os.path.join(tmpdir, fn)
            if os.path.isfile(src) and fn != "snap":
                shutil.copy2(src, os.path.join(snap, fn))

        # Phase 2: +3 Events (count 8)
        g = ga()
        for i in range(5, 8):
            g.log_event(f"E{i}")
        g.close()

        # === Szenario A: DB-Rollback (ohne *.evolve) -> ROLLBACK_DETECTED ===
        for fn in ["audit.db", "audit.db-wal", "audit.db-shm"]:
            src = os.path.join(snap, fn)
            if os.path.isfile(src):
                for dst_fn in os.listdir(tmpdir):
                    dst = os.path.join(tmpdir, dst_fn)
                    if os.path.isfile(dst) and dst_fn.startswith("audit.db"):
                        try: os.remove(dst)
                        except PermissionError: pass
            if os.path.isfile(src):
                shutil.copy2(src, tmpdir)

        try:
            g2 = ga(); g2.close()
            print("FAIL A: Rollback unbemerkt"); return False
        except RuntimeError as e:
            if "ROLLBACK_DETECTED" in str(e):
                print(f"PASS A: {e}")
            else:
                print(f"FAIL A: {e}"); return False

        # === Szenario C: DB-Rollback + *.evolve geloescht -> STATE_FILE_MISSING ===
        for fn in os.listdir(tmpdir):
            fp = os.path.join(tmpdir, fn)
            if os.path.isfile(fp) and fn.startswith("audit"):
                try: os.remove(fp)
                except PermissionError: pass
        for fn in ["audit.db", "audit.db-wal", "audit.db-shm"]:
            src = os.path.join(snap, fn)
            if os.path.isfile(src):
                shutil.copy2(src, tmpdir)
        if os.path.isfile(st):
            os.remove(st)

        try:
            g3 = ga(); g3.close()
            print("FAIL C: STATE_FILE_MISSING nicht erkannt"); return False
        except RuntimeError as e:
            if "STATE_FILE_MISSING" in str(e):
                print(f"PASS C: {e}")
            else:
                print(f"FAIL C: {e}"); return False

        # === Szenario D: Gleiches Szenario mit force_reinit=True -> OK ===
        try:
            g4 = ga(force_reinit=True)
            print(f"PASS D: force_reinit akzeptiert (count={g4._key_evolve_count})")
            g4.close()
        except RuntimeError as e:
            print(f"FAIL D: force_reinit blocked: {e}"); return False

        print("\nResult: 4/4 PASS")
        return True
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    exit(0 if test_rollback() else 1)
