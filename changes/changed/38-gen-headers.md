- `make gen` opens every generated assembly file with a comment block: its
  licence (SPDX), its path, set, hash variant and target, the CPU features
  the unit needs, the regeneration commands, a note that its symbols are
  not API, and where the assurance of the assembly ends. `gen/MANIFEST`
  carries SPDX lines. The block is the same on every host, so
  `make gen-check` still compares the files byte for byte.
