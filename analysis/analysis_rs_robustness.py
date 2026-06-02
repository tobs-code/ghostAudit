from reedsolo import RSCodec, ReedSolomonError
import random

def analyze_rs_capacity(msg_len, ecc_symbols):
    rs = RSCodec(ecc_symbols)
    # Total symbols = msg_len + ecc_symbols
    # Correctable errors (t) = ecc_symbols // 2
    t = ecc_symbols // 2
    
    print(f"--- RS Analysis (Data: {msg_len}, Parity: {ecc_symbols}) ---")
    print(f"Max correctable symbol errors (t): {t}")
    
    data = ("A" * msg_len).encode()
    encoded = bytearray(rs.encode(data))
    
    # 1. Test symbol errors
    corrupted = bytearray(encoded)
    for i in range(t):
        corrupted[i] = (corrupted[i] + 1) % 256
    
    try:
        rs.decode(corrupted)
        print(f"SUCCESS: Corrected {t} symbol errors.")
    except ReedSolomonError:
        print(f"FAILURE: Could not correct {t} symbol errors.")

    # 2. Test Point of No Return
    corrupted_over = bytearray(encoded)
    for i in range(t + 1):
        corrupted_over[i] = (corrupted_over[i] + 1) % 256
    
    try:
        rs.decode(corrupted_over)
        print(f"SUCCESS: Corrected {t+1} symbol errors (Unexpected!)")
    except ReedSolomonError:
        print(f"FAILURE: {t+1} symbol errors is the Point of No Return.")

    # 3. Bit-to-Symbol Analysis (GhostAudit scenario)
    # 1 row = 1 bit. 1 byte = 8 bits.
    # If we wipe X rows, how many symbols are affected?
    # Case A: Wiping a continuous block of rows
    # Rows 0-7 belong to Symbol 0. Wiping all 8 rows only costs 1 symbol.
    print("\n--- GhostAudit Bit-to-Symbol Mapping ---")
    rows_per_symbol = 8
    burst_rows_to_wipe = t * rows_per_symbol
    print(f"Burst Attack: Wiping {burst_rows_to_wipe} consecutive rows affects {t} symbols.")
    
    # Case B: Distributed Attack
    # Wiping rows 0, 8, 16, 24, 32, 40... 
    # Each row belongs to a DIFFERENT symbol.
    dist_rows_to_wipe = t + 1
    print(f"Distributed Attack: Wiping {dist_rows_to_wipe} specific rows can affect {t+1} symbols.")

if __name__ == "__main__":
    # Current GhostAudit V2 config: ecc_symbols=10
    analyze_rs_capacity(msg_len=20, ecc_symbols=10)
