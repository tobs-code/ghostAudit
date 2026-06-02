h_bits=[0,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,0,0,0,0,0]
candidate=bytes.fromhex('57001e0200000001')
candidate_bits=[]
for b in candidate:
    candidate_bits.extend([int(x) for x in format(b,'08b')])
print('candidate bits first 32:', candidate_bits[:32])
print('h_bits first 32:', h_bits[:32])
diffs=[i for i in range(min(len(candidate_bits), len(h_bits))) if candidate_bits[i]!=h_bits[i]]
print('diffs', diffs)
