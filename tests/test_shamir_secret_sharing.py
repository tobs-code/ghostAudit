import os
import sys
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.shamir_secret_sharing import (
    split_secret,
    reconstruct_secret,
    create_share_db,
    write_share,
    read_share,
    read_all_shares,
    reconstruct_from_sources,
)


def _cleanup(*paths):
    for p in paths:
        if os.path.exists(p):
            os.remove(p)


def test_sss_split_and_reconstruct():
    secret = b"this is a 32-byte master key!!!!!"
    n, k = 5, 3
    shares = split_secret(secret, n, k)
    assert len(shares) == n

    recovered = reconstruct_secret(shares[:k])
    assert recovered == secret, f"len={len(recovered)} expected={len(secret)}"

    # auch mit anderer Kombination
    recovered2 = reconstruct_secret([shares[1], shares[3], shares[4]])
    assert recovered2 == secret


def test_sss_wrong_threshold_fails():
    secret = b"threshold test key 1234"
    shares = split_secret(secret, 5, 3)
    recovered = reconstruct_secret(shares[:2])
    assert recovered != secret, "2 shares should not reconstruct a 3-of-5 secret"


def test_sss_any_k_of_n():
    secret = b"any 3 of 5 shall work"
    shares = split_secret(secret, 5, 3)
    import itertools
    for combo in itertools.combinations(range(5), 3):
        recovered = reconstruct_secret([shares[i] for i in combo])
        assert recovered == secret, f"combo {combo} failed"


def test_sss_binary_secret():
    secret = os.urandom(64)
    shares = split_secret(secret, 5, 3)
    recovered = reconstruct_secret(shares[:3])
    assert recovered == secret


def test_sss_single_byte():
    secret = b"\xAB"
    shares = split_secret(secret, 3, 2)
    recovered = reconstruct_secret(shares[:2])
    assert recovered == secret


def test_sss_large_secret():
    secret = os.urandom(1024)
    shares = split_secret(secret, 7, 4)
    recovered = reconstruct_secret(shares[:4])
    assert recovered == secret


def test_sql_write_read_share():
    db = os.path.join(tempfile.gettempdir(), "test_shamir_share.db")
    _cleanup(db)
    try:
        create_share_db(db)
        write_share(db, "shamir_shares", 1, b"share_value_123")
        val = read_share(db, "shamir_shares", 1)
        assert val == b"share_value_123", f"got {val!r}"

        val2 = read_share(db, "shamir_shares", 99)
        assert val2 is None
    finally:
        _cleanup(db)


def test_sql_read_all():
    db = os.path.join(tempfile.gettempdir(), "test_shamir_readall.db")
    _cleanup(db)
    try:
        create_share_db(db)
        write_share(db, "shamir_shares", 1, b"share_1")
        write_share(db, "shamir_shares", 2, b"share_2")
        write_share(db, "shamir_shares", 3, b"share_3")
        all_ = read_all_shares(db, "shamir_shares")
        assert len(all_) == 3
        assert all_[0] == (1, b"share_1")
        assert all_[1] == (2, b"share_2")
        assert all_[2] == (3, b"share_3")
    finally:
        _cleanup(db)


def test_sql_sss_roundtrip():
    secret = b"sql-split-master-key-42"
    n, k = 5, 3
    shares = split_secret(secret, n, k)

    dbs = []
    try:
        for i in range(n):
            db = os.path.join(tempfile.gettempdir(), f"test_shamir_{i}.db")
            dbs.append(db)
            create_share_db(db)
            write_share(db, "shamir_shares", i + 1, shares[i][1])

        sources = [(dbs[i], "shamir_shares", i + 1) for i in range(k)]
        recovered = reconstruct_from_sources(sources)
        assert recovered == secret
    finally:
        for db in dbs:
            _cleanup(db)


def test_ghostaudit_with_shares():
    from core.ghost_audit_v7 import GhostAuditV7
    master_key = b"threshold-master-key-42!"

    n, k = 3, 2
    shares = split_secret(master_key, n, k)
    dbs = []
    ga_path = os.path.join(tempfile.gettempdir(), "test_ga_shares.db")
    _cleanup(ga_path, os.path.splitext(ga_path)[0] + ".evolve")
    ga = None
    try:
        for i in range(n):
            db = os.path.join(tempfile.gettempdir(), f"test_ga_share_{i}.db")
            dbs.append(db)
            create_share_db(db)
            write_share(db, "shamir_shares", i + 1, shares[i][1])

        sources = [(dbs[i], "shamir_shares", i + 1) for i in range(k)]
        ga = GhostAuditV7(db_path=ga_path, shares=sources, verbose=False)
        ga.log_event("Event from shares")
        recovered = ga.recover_events()
        assert len(recovered) == 1
        assert recovered[0][1] == "Event from shares"
    finally:
        if ga:
            ga.close()
        _cleanup(ga_path, os.path.splitext(ga_path)[0] + ".evolve")
        for db in dbs:
            _cleanup(db)
