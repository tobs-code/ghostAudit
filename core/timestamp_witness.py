import hashlib
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import Any

import requests
import rfc3161ng

logger = logging.getLogger(__name__)

WITNESS_QUEUE_TABLE = "sys_witness_queue"

WITNESS_QUEUE_DDL = f"""
CREATE TABLE IF NOT EXISTS {WITNESS_QUEUE_TABLE} (
    seq          INTEGER PRIMARY KEY,
    evolve_path  TEXT    NOT NULL,
    digest_hex   TEXT    NOT NULL,
    state        TEXT    DEFAULT 'pending',
    tst_der      BLOB,
    tsa_url      TEXT,
    submitted_at INTEGER,
    confirmed_at INTEGER
);
"""

FREETSA_CERT_PEM = b"""
-----BEGIN CERTIFICATE-----
MIIGYDCCBEigAwIBAgIJAMLphhYNqOnNMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMjYwMjE1MTk0NDIyWhcNNDAwMjAyMTk0NDIyWjCCAQsxETAPBgNVBAoMCEZy
ZWUgVFNBMQwwCgYDVQQLDANUU0ExdjB0BgNVBA0MbVRoaXMgY2VydGlmaWNhdGUg
ZGlnaXRhbGx5IHNpZ25zIGRvY3VtZW50cyBhbmQgdGltZSBzdGFtcCByZXF1ZXN0
cyBtYWRlIHVzaW5nIHRoZSBmcmVldHNhLm9yZyBvbmxpbmUgc2VydmljZXMxGDAW
BgNVBAMMD3d3dy5mcmVldHNhLm9yZzEkMCIGCSqGSIb3DQEJARYVYnVzaWxlemFz
QG1haWxib3gub3JnMRIwEAYDVQQHDAlXdWVyemJ1cmcxCzAJBgNVBAYTAkRFMQ8w
DQYDVQQIDAZCYXllcm4wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASiFeGhstbLhxix
0o4UAumNSwHUUlOe3DBvs8fYs580wADW59oqGSCx15bp61TSmXkwLm1JW48XnbLL
izP6ZtjcvshV3H9uz2bS53sgDXhg1wLbIhAtraC+fHCytHeuVaujggHmMIIB4jAJ
BgNVHRMEAjAAMB0GA1UdDgQWBBQVwL0m69RdgtFdkyYxL+9wsotGXjAfBgNVHSME
GDAWgBT6VQ2MNGZRQ0z357OnbJWveuaklzALBgNVHQ8EBAMCBsAwFgYDVR0lAQH/
BAwwCgYIKwYBBQUHAwgwbAYIKwYBBQUHAQEEYDBeMDMGCCsGAQUFBzAChidodHRw
Oi8vd3d3LmZyZWV0c2Eub3JnL2ZpbGVzL2NhY2VydC5wZW0wJwYIKwYBBQUHMAGG
G2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDA3BgNVHR8EMDAuMCygKqAohiZo
dHRwOi8vd3d3LmZyZWV0c2Eub3JnL2NybC9yb290X2NhLmNybDCByAYDVR0gBIHA
MIG9MIG6BgMrBQgwgbIwMwYIKwYBBQUHAgEWJ2h0dHA6Ly93d3cuZnJlZXRzYS5v
cmcvZnJlZXRzYV9jcHMuaHRtbDAyBggrBgEFBQcCARYmaHR0cDovL3d3dy5mcmVl
dHNhLm9yZy9mcmVldHNhX2Nwcy5wZGYwRwYIKwYBBQUHAgIwOxo5RnJlZVRTQSB0
cnVzdGVkIHRpbWVzdGFtcGluZyBTb2Z0d2FyZSBhcyBhIFNlcnZpY2UgKFNhYVMp
MA0GCSqGSIb3DQEBDQUAA4ICAQBrMVS/YfnfMr0ziZnesBUOrDNRrNNgt3IgMNDw
Nhwl6oKWHVIhlYnM/5boljfbpZTAbqvxHI3ztT0/swxQOqTat5qBJRAY/VH1n/T4
M9uDjSuu3qfh0ZH5PL9ENqoVW44i5NT/znQev2MGXOAHwz9kZwwzz9MFX6hbGhBq
Wa+nlAqb7Y72KFzj33m1OVHxV2Wl4YD9f91bZTFpUEGW4Ktbkmxpf/iGIPaf4WHp
oBW/O6EzofMKYlz4yXyEBh0wRRVyXltLrj+MFHqhe+PsMBllq/dCaO4W/F+AuHEl
u7aUYWMASelphWAJiUsNMr5HAoeCSSgilqf1CSoWC+k6e4334Fym+Iy4csMex+PG
4rSdqXJVQ+AWEdRajSPKh7yDfpNkdnO6yqQJ/tSd11XQ5cL0M9jWuCD1zHlgA+u+
R2cry3yo23jD7qTGLhZqUvXCyWigH30/Q/RXjjDwrc4DJiQ+gRY0FhdTYqlvgMBP
r4LcJKnNksivdj+kbz7bVSbrBAzRiazK9l841/5XMtP9BvD0hKCpQFvP9PSgCC8E
QnKqgSe26FSJBaAQcA5TnK8NF4jkbElBxf/zyh7P3IjHso35jtgUWD1/itg9BJWb
YUwJ4tfILpB2F0wbk1GcZDCDZoyW3Xf3trApz/Zd93gF3joc9Hh9RFveKRzWQ7dd
Ut3egQ==
-----END CERTIFICATE-----
"""

CACERT_PEM = b"""
-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----
"""

TSA_LIST: list[tuple[str, bytes]] = [
    ("https://freetsa.org/tsr", FREETSA_CERT_PEM),
    ("https://timestamp.digicert.com", b""),
    ("https://tsa.sectigo.com", b""),
]


@dataclass
class WitnessReceipt:
    seq: int = 0
    digest_hex: str = ""
    timestamp: int = 0
    tst_der: bytes = field(default_factory=bytes)
    tsa_url: str = ""
    state: str = "pending"


class TimestampWitness:
    def __init__(
        self,
        db_path: str,
        evolve_path: str | None = None,
        poll_interval: float = 30.0,
        max_pending_age: float = 300.0,
    ):
        self._db_path = db_path
        self._evolve_path = evolve_path
        self._poll_interval = poll_interval
        self._max_pending_age = max_pending_age
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._tsa_list: list[tuple[str, bytes]] = TSA_LIST[:]
        self._warned_stale = False
        self._worker_conn: sqlite3.Connection | None = None

        with sqlite3.connect(db_path) as init_conn:
            init_conn.execute(WITNESS_QUEUE_DDL)
            init_conn.commit()

        if self._evolve_path:
            self.start()

    def _ensure_table(self) -> None:
        cur = self._conn.cursor()
        cur.execute(WITNESS_QUEUE_DDL)
        self._conn.commit()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._worker_loop, daemon=False, name="tsa-witness"
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _worker_loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            try:
                self._process_pending()
            except Exception:
                logger.exception("Witness worker error")

    def _process_pending(self) -> None:
        conn = sqlite3.connect(self._db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                f"SELECT seq, evolve_path, digest_hex FROM {WITNESS_QUEUE_TABLE} "
                f"WHERE state='pending' ORDER BY seq ASC"
            )
            rows = cur.fetchall()
            if not rows:
                return
            for seq, evolve_path, stored_digest in rows:
                if not evolve_path:
                    continue
                try:
                    current_digest = self._sha256_file(evolve_path)
                except (OSError, FileNotFoundError):
                    continue
                if not current_digest or current_digest != stored_digest:
                    continue
                receipt = self.submit(seq, evolve_path, current_digest)
                if receipt is not None:
                    conn.execute(
                        f"UPDATE {WITNESS_QUEUE_TABLE} SET "
                        f"state='confirmed', tst_der=?, tsa_url=?, "
                        f"confirmed_at=? WHERE seq=?",
                        (
                            receipt.tst_der,
                            receipt.tsa_url,
                            int(time.time() * 1000),
                            seq,
                        ),
                    )
                    conn.commit()
        finally:
            conn.close()

    def add_pending(self, seq: int, evolve_path: str) -> None:
        if not evolve_path:
            return
        try:
            digest_hex = self._sha256_file(evolve_path)
        except (OSError, FileNotFoundError):
            return
        if not digest_hex:
            return
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO {WITNESS_QUEUE_TABLE} "
                f"(seq, evolve_path, digest_hex, state, submitted_at) "
                f"VALUES (?, ?, ?, 'pending', ?)",
                (seq, evolve_path, digest_hex, int(time.time() * 1000)),
            )
            conn.commit()

    def submit(
        self, seq: int, evolve_path: str, digest_hex: str | None = None
    ) -> WitnessReceipt | None:
        if digest_hex is None:
            try:
                digest_hex = self._sha256_file(evolve_path)
            except (OSError, FileNotFoundError):
                return None
        if not digest_hex:
            return None
        digest_bytes = bytes.fromhex(digest_hex)
        for tsa_url, tsa_cert_pem in self._tsa_list:
            try:
                request = rfc3161ng.make_timestamp_request(
                    digest=digest_bytes, hashname="sha256"
                )
                resp = requests.post(
                    tsa_url,
                    data=request,
                    headers={"Content-Type": "application/timestamp-query"},
                    timeout=5.0,
                )
                resp.raise_for_status()
                tst_der = resp.content
                if tsa_cert_pem:
                    cert = rfc3161ng.TrustedCertificate(tsa_cert_pem)
                    tsr = rfc3161ng.decode_timestamp_response(tst_der)
                    if not rfc3161ng.check_timestamp(
                        tsr, digest=digest_bytes, hashname="sha256", trusted_certificate=cert
                    ):
                        continue
                timestamp = int(time.time() * 1000)
                return WitnessReceipt(
                    seq=seq,
                    digest_hex=digest_hex,
                    timestamp=timestamp,
                    tst_der=tst_der,
                    tsa_url=tsa_url,
                    state="confirmed",
                )
            except Exception:
                logger.debug("TSA %s failed", tsa_url, exc_info=True)
                continue
        return None

    def verify(self, receipt: WitnessReceipt) -> bool:
        if receipt.state != "confirmed" or not receipt.tst_der:
            return False
        tsa_cert_pem = b""
        for url, cert in self._tsa_list:
            if url == receipt.tsa_url:
                tsa_cert_pem = cert
                break
        if not tsa_cert_pem:
            return False
        try:
            cert = rfc3161ng.TrustedCertificate(tsa_cert_pem)
            tsr = rfc3161ng.decode_timestamp_response(receipt.tst_der)
            return rfc3161ng.check_timestamp(
                tsr,
                digest=bytes.fromhex(receipt.digest_hex),
                hashname="sha256",
                trusted_certificate=cert,
            )
        except Exception:
            return False

    def get_status(self) -> dict:
        with sqlite3.connect(self._db_path) as conn:
            cur = conn.cursor()
            cur.execute(
                f"SELECT seq, state, tsa_url, confirmed_at FROM {WITNESS_QUEUE_TABLE} "
                f"ORDER BY seq DESC LIMIT 5"
            )
            entries = []
            for row in cur.fetchall():
                entries.append({
                    "seq": row[0],
                    "state": row[1],
                    "tsa_url": row[2] or "",
                    "confirmed_at": row[3] or 0,
                })
            cur.execute(
                f"SELECT MIN(submitted_at) FROM {WITNESS_QUEUE_TABLE} WHERE state='pending'"
            )
            oldest_pending_submitted = cur.fetchone()[0]
            cur.execute(
                f"SELECT COUNT(*) FROM {WITNESS_QUEUE_TABLE} WHERE state='pending'"
            )
            pending_count = cur.fetchone()[0]
            cur.execute(
                f"SELECT COUNT(*) FROM {WITNESS_QUEUE_TABLE}"
            )
            total_entries = cur.fetchone()[0]

        now_ms = int(time.time() * 1000)
        oldest_pending_age_ms = (now_ms - oldest_pending_submitted) if oldest_pending_submitted else 0

        if pending_count == 0:
            health = "healthy"
            self._warned_stale = False
        elif oldest_pending_age_ms < self._max_pending_age * 1000:
            health = "degraded"
            self._warned_stale = False
        else:
            health = "stale"
            if not self._warned_stale:
                logger.warning(
                    "Witness stale: %d pending entries, oldest %.0fs old (max %.0fs). "
                    "TSA may be unreachable.",
                    pending_count, oldest_pending_age_ms / 1000, self._max_pending_age,
                )
                self._warned_stale = True

        return {
            "evolve_path": self._evolve_path,
            "pending_count": pending_count,
            "total_entries": total_entries,
            "oldest_pending_age_ms": oldest_pending_age_ms,
            "health": health,
            "max_pending_age_s": self._max_pending_age,
            "recent": entries,
            "thread_alive": self._thread is not None and self._thread.is_alive(),
        }

    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
