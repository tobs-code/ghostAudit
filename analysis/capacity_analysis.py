import os
import json

def run_analysis(per_channel_min_reps=5, ecc_max=64):
    # Set env before importing module so class-level defaults pick it up
    os.environ["GHOST_AUDIT_PER_CHANNEL_MIN_REPS"] = str(per_channel_min_reps)

    from core.ghost_audit_v7 import GhostAuditV7

    ghost = GhostAuditV7(db_path=":memory:", secret_key="capkey", ecc_symbols=ecc_max, verbose=False)

    payload_rows = ghost.SLOT_SIZE - ghost.HEADER_BIT_COUNT
    rows_per_channel_slot = payload_rows // ghost.CHANNEL_COUNT

    results = []
    for stored_msg_len in list(range(10, 201, 10)) + [300, 500]:
        stored_msg_len = int(stored_msg_len)
        selected_nsym = ghost._select_ecc_symbols(stored_msg_len, rows_per_channel_slot, per_channel=True)

        payload_bytes = b"\x00" * (16 + stored_msg_len)
        channel_blocks = ghost._encode_payload_per_channel_v7(payload_bytes, selected_nsym)
        max_enc_len = max(len(channel_blocks[c]) for c in range(ghost.CHANNEL_COUNT))

        pc_min_rep = ghost._per_channel_min_repetitions(stored_msg_len, selected_nsym, rows_per_channel_slot)
        max_ch_bits_per_slot = rows_per_channel_slot // max(1, pc_min_rep)
        max_ch_bytes_per_slot = max(1, max_ch_bits_per_slot // 8)

        fragment_count = (max_enc_len + max_ch_bytes_per_slot - 1) // max_ch_bytes_per_slot
        fits = fragment_count <= ghost.SLOT_COUNT

        results.append({
            "stored_msg_len": stored_msg_len,
            "selected_nsym": selected_nsym,
            "max_enc_len_bytes": max_enc_len,
            "pc_min_rep": pc_min_rep,
            "rows_per_channel_slot": rows_per_channel_slot,
            "max_ch_bytes_per_slot": max_ch_bytes_per_slot,
            "fragment_count": fragment_count,
            "fits": fits,
        })

    print(json.dumps({"per_channel_min_reps": per_channel_min_reps, "ecc_max": ecc_max, "results": results}, indent=2))

if __name__ == "__main__":
    import sys
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    ecc = int(sys.argv[2]) if len(sys.argv) > 2 else 64
    run_analysis(reps, ecc)
