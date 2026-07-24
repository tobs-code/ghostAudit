"""Tests für das MetricRegistry-Interface."""

import os
import tempfile
import time

from unittest.mock import MagicMock

from core.metrics import NoopMetricRegistry
from core.ghost_audit_v9 import GhostAuditInterceptor


def test_noop_registry_zero_cost():
    """Noop-Registry schluckt alle Aufrufe ohne Exception oder Seiteneffekte."""
    registry = NoopMetricRegistry()

    counter = registry.counter("test", "test counter", ["channel"])
    counter.inc()
    counter.inc(5.0)
    counter.inc(channel="ui_prefs")
    counter.inc(3.0, channel="trust_score")

    gauge = registry.gauge("test2", "test gauge", [])
    gauge.set(42)
    gauge.inc()
    gauge.dec()
    gauge.inc(10.0)
    gauge.dec(5.0)

    gauge_with_labels = registry.gauge("test3", "test gauge with labels", ["status"])
    gauge_with_labels.set(1, status="success")
    gauge_with_labels.inc(status="fail")
    gauge_with_labels.dec(status="partial")


def test_noop_default_in_interceptor():
    """GhostAuditInterceptor nutzt NoopMetricRegistry wenn keins übergeben."""

    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "test.db")
    try:
        ga = GhostAuditInterceptor(db_path, verbose=False)
        # Hat die Metriken initialisiert (Noop) ohne zu crashen
        assert ga._erasure_total is not None
        assert ga._recovery_total is not None
        assert ga._pending_payloads is not None
        # Alle Aufrufe sind Noops — keine Exception
        ga._erasure_total.inc(channel="test")
        ga._recovery_total.inc(status="success")
        ga._pending_payloads.inc()
        ga._pending_payloads.dec()
        ga._pending_payloads.set(0)
    finally:
        ga.close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_try_flush_size_trigger():
    """try_flush flusht wenn auto_flush_completed erreicht."""
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "test.db")
    try:
        ga = GhostAuditInterceptor(db_path, verbose=False,
                                   auto_flush_completed=3)
        ga.flush_headers = MagicMock(return_value=1)  # type: ignore[method-assign]
        assert ga.try_flush() == 0  # leere Queue, kein Trigger
        ga._completed_payloads.append("p1")
        assert ga.try_flush() == 0  # 1/3, unter Schwelle
        ga._completed_payloads.append("p2")
        assert ga.try_flush() == 0  # 2/3, unter Schwelle
        ga._completed_payloads.append("p3")
        result = ga.try_flush()
        assert result > 0           # 3/3, Size-Trigger feuert
        ga.flush_headers.assert_called_once()
    finally:
        ga.close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_try_flush_time_trigger():
    """try_flush flusht wenn auto_flush_interval abgelaufen."""
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "test.db")
    try:
        ga = GhostAuditInterceptor(db_path, verbose=False,
                                   auto_flush_interval=0.1,
                                   auto_flush_completed=999)
        ga.flush_headers = MagicMock(return_value=2)  # type: ignore[method-assign]
        assert ga.try_flush() == 0  # _last_flush_ts == 0, kein Trigger
        ga._last_flush_ts = time.monotonic() - 0.2   # simuliere abgelaufenes Intervall
        ga._completed_payloads.append("p1")
        result = ga.try_flush()
        assert result > 0           # Time-Trigger feuert
        ga.flush_headers.assert_called_once()
    finally:
        ga.close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_integrity_no_false_positive():
    """verify_pending_queue_integrity: kein Gap wenn Event noch pending."""
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "test.db")
    try:
        ga = GhostAuditInterceptor(db_path, verbose=False)
        seq = ga.log_structured_event(event_type="test", value=42)
        assert seq is not None
        # Event in audit_log + pending queue → kein Gap
        missing = ga.verify_pending_queue_integrity(recovered_seqs=set())
        assert missing == [], f"Expected no gap, got {missing}"
    finally:
        ga.close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_integrity_detects_gap():
    """verify_pending_queue_integrity: Gap bei gelöschtem Pending-Row."""
    tmp = tempfile.mkdtemp()
    db_path = os.path.join(tmp, "test.db")
    try:
        ga = GhostAuditInterceptor(db_path, verbose=False)
        seq = ga.log_structured_event(event_type="secret", value=99)
        assert seq is not None
        # Pending Queue-Row löschen (simulierter Angriff)
        cursor = ga._engine.conn.cursor()
        cursor.execute("DELETE FROM ghostaudit_pending_queue WHERE seq = ?", (seq,))
        ga._engine.conn.commit()
        # audit_log hat den Event, aber weder pending noch recovered
        missing = ga.verify_pending_queue_integrity(recovered_seqs=set())
        assert seq in missing, f"Expected seq {seq} in missing, got {missing}"
    finally:
        ga.close()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
