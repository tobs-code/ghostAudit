"""Tests für das MetricRegistry-Interface."""

from core.metrics import NoopMetricRegistry


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
    import tempfile
    import os
    from core.ghost_audit_v9 import GhostAuditInterceptor

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
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
