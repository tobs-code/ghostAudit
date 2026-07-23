from abc import ABC, abstractmethod
from typing import Any


# ---------------------------------------------------------------------------
# Metric interfaces — abstract over Prometheus / noop backends
# ---------------------------------------------------------------------------

class Counter(ABC):
    @abstractmethod
    def inc(self, amount: float = 1.0, **labels: str | int) -> None: ...


class Gauge(ABC):
    @abstractmethod
    def set(self, value: float, **labels: str | int) -> None: ...

    @abstractmethod
    def inc(self, amount: float = 1.0, **labels: str | int) -> None: ...

    @abstractmethod
    def dec(self, amount: float = 1.0, **labels: str | int) -> None: ...


class MetricRegistry(ABC):
    @abstractmethod
    def counter(self, name: str, desc: str, labels: list[str]) -> Counter:
        ...

    @abstractmethod
    def gauge(self, name: str, desc: str, labels: list[str]) -> Gauge:
        ...


# ---------------------------------------------------------------------------
# Noop implementations — zero overhead when no monitoring is configured
# ---------------------------------------------------------------------------

class _NoopCounter(Counter):
    def inc(self, amount: float = 1.0, **labels: str | int) -> None:
        pass


class _NoopGauge(Gauge):
    def set(self, value: float, **labels: str | int) -> None:
        pass

    def inc(self, amount: float = 1.0, **labels: str | int) -> None:
        pass

    def dec(self, amount: float = 1.0, **labels: str | int) -> None:
        pass


class NoopMetricRegistry(MetricRegistry):
    def counter(self, name: str, desc: str, labels: list[str]) -> Counter:
        return _NoopCounter()

    def gauge(self, name: str, desc: str, labels: list[str]) -> Gauge:
        return _NoopGauge()


# ---------------------------------------------------------------------------
# Prometheus implementation
# ---------------------------------------------------------------------------

class _PrometheusCounter(Counter):
    def __init__(self, prom_counter: Any):
        self._counter = prom_counter

    def inc(self, amount: float = 1.0, **labels: str | int) -> None:
        if labels:
            self._counter.labels(**labels).inc(amount)
        else:
            self._counter.inc(amount)


class _PrometheusGauge(Gauge):
    def __init__(self, prom_gauge: Any):
        self._gauge = prom_gauge

    def set(self, value: float, **labels: str | int) -> None:
        if labels:
            self._gauge.labels(**labels).set(value)
        else:
            self._gauge.set(value)

    def inc(self, amount: float = 1.0, **labels: str | int) -> None:
        if labels:
            self._gauge.labels(**labels).inc(amount)
        else:
            self._gauge.inc(amount)

    def dec(self, amount: float = 1.0, **labels: str | int) -> None:
        if labels:
            self._gauge.labels(**labels).dec(amount)
        else:
            self._gauge.dec(amount)


class PrometheusMetricRegistry(MetricRegistry):
    def __init__(self, namespace: str = "ghostaudit"):
        from prometheus_client import Counter as PCounter, Gauge as PGauge
        from prometheus_client import Histogram as PHistogram
        self._namespace = namespace
        self._PCounter = PCounter
        self._PGauge = PGauge
        self._PHistogram = PHistogram
        self._counters: dict[str, Any] = {}
        self._gauges: dict[str, Any] = {}

    def counter(self, name: str, desc: str, labels: list[str]) -> Counter:
        full_name = f"{self._namespace}_{name}"
        if full_name not in self._counters:
            self._counters[full_name] = self._PCounter(full_name, desc, labels)
        return _PrometheusCounter(self._counters[full_name])

    def gauge(self, name: str, desc: str, labels: list[str]) -> Gauge:
        full_name = f"{self._namespace}_{name}"
        if full_name not in self._gauges:
            self._gauges[full_name] = self._PGauge(full_name, desc, labels)
        return _PrometheusGauge(self._gauges[full_name])
