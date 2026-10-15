- More negative tests: pure and pre-hash signatures, and signatures under
  different pre-hash functions, rejected for one another; internal and
  external signatures kept apart; all-zero and all-0xFF keys; messages that
  leave the input of H_msg or PRF_msg at the edges of a hash block, and of
  1 MiB; contexts of 0, 1, 254 and 255 bytes;
  every set signing on concurrent threads; buffers at every alignment.
- `make check` builds and runs the C example of `README.md`, and a copy
  with one flipped signature bit that must report it invalid.
