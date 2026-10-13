- Multi-way hashing in the hash layer: 4-way Keccak-f[1600] with a 4-way
  sponge, 8-way SHA-256 and 4-way SHA-512. Each computes independent
  instances side by side, with the same results as the single-way
  functions. The kernels in this change are portable scalar code.
