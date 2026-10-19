- The SHA-256 and SHA-512 absorb functions reduce the remaining input length
  modulo the block size after the whole-block step on both paths, not only
  after whole blocks were compressed, so that the bound on the copy into the
  block buffer is explicit in the code rather than implied by the whole-block
  count. Outputs are unchanged; the extracted models and the streaming SHA-2
  correctness proofs follow the new form.
