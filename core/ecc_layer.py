import numpy as np

class Hamming74:
    """
    Implementation of Hamming (7,4) error correction code.
    Can correct 1-bit error in each 7-bit block.
    """
    
    # Generator matrix G
    G = np.array([
        [1, 1, 0, 1],
        [1, 0, 1, 1],
        [1, 0, 0, 0],
        [0, 1, 1, 1],
        [0, 1, 0, 0],
        [0, 0, 1, 0],
        [0, 0, 0, 1]
    ])
    
    # Parity check matrix H
    H = np.array([
        [1, 0, 1, 0, 1, 0, 1],
        [0, 1, 1, 0, 0, 1, 1],
        [0, 0, 0, 1, 1, 1, 1]
    ])

    @staticmethod
    def encode(data_4bits):
        """Encodes 4 bits into 7 bits."""
        if len(data_4bits) != 4:
            raise ValueError("Data must be 4 bits")
        d = np.array(data_4bits).reshape(4, 1)
        c = np.dot(Hamming74.G, d) % 2
        return c.flatten().tolist()

    @staticmethod
    def decode(code_7bits):
        """Decodes 7 bits back to 4 bits, correcting up to 1 error."""
        if len(code_7bits) != 7:
            raise ValueError("Code must be 7 bits")
        c = np.array(code_7bits).reshape(7, 1)
        s = np.dot(Hamming74.H, c) % 2
        
        # If syndrome s is non-zero, there is an error
        syndrome_val = s[0][0] + s[1][0]*2 + s[2][0]*4
        if syndrome_val != 0:
            # Error at index syndrome_val - 1
            error_idx = int(syndrome_val - 1)
            c[error_idx] = (c[error_idx] + 1) % 2
            
        # Extract data bits (indices 2, 4, 5, 6 in our G matrix)
        # Based on G: G[2]=d0, G[4]=d1, G[5]=d2, G[6]=d3
        return [int(c[2]), int(c[4]), int(c[5]), int(c[6])]

def string_to_bits(s):
    return [int(b) for b in ''.join(format(ord(c), '08b') for c in s)]

def bits_to_string(bits):
    s = ""
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) == 8:
            byte_str = "".join(map(str, byte_bits))
            s += chr(int(byte_str, 2))
    return s

if __name__ == "__main__":
    # Test Hamming 7,4
    data = [1, 0, 1, 1]
    encoded = Hamming74.encode(data)
    print(f"Original: {data}")
    print(f"Encoded:  {encoded}")
    
    # Introduce error
    encoded[2] = (encoded[2] + 1) % 2
    print(f"Corrupted: {encoded}")
    
    decoded = Hamming74.decode(encoded)
    print(f"Decoded:   {decoded}")
