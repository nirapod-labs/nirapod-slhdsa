- More of the SLH-DSA core is written in the forms the Jasmin safety checker
  can bound; behaviour is unchanged. The FORS tree, authentication-path,
  selected-leaf and root buffers, the XMSS authentication path and WOTS+
  signature, the framed message prefix and the SHA-2 block buffers of
  PRF_msg and H_msg are written at constant indices before use, and the
  SHA-2 tweakable hash clears its whole message buffer. FORS tree and
  hypertree layer signatures, the pre-hash in the framed prefix and the
  message of the SHA-2 tweakable hash are stored at a fixed base plus an
  offset derived from the loop counter. The SHAKE absorb positions, the
  pre-hash length and the framed prefix length are clamped to bounds they
  already meet, so the clamps never change a value. Keys and signatures
  are unchanged. `make fill-check` now covers 11 fill sites (7 new) and
  `make fill-check-controls` 15 filled buffers (11 new). The whole-buffer
  clear is not a fill, and the fill check does not rewrite it: the bytes
  it adds lie past the padded message and are never hashed. `make
  checker-repro` re-checks three more checker limitations: an offset
  advanced beside its loop counter, a position reset on equality, and a
  block offset bounded only by its loop test, which reaches past a partly
  cleared buffer.
