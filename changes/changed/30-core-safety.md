- The SLH-DSA core writes four stack buffers at constant indices before
  use, clamps the tree-height index of the treehash fold, and passes the
  message pointer and length to the message hashes as scalars instead of in
  an array, so that the Jasmin safety checker can follow them. Keys and
  signatures are unchanged. `make fill-check` builds the library with those
  buffers pre-filled with 0xa5 bytes and runs the known answers on it, and
  `make checker-repro` re-checks the three checker limitations behind these
  changes.
