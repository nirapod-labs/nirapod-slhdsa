- The repository carries the generated assembly of every target in `gen/`,
  with `gen/MANIFEST`, so `make` and `make check` need only a C compiler,
  the platform's assembler and linker, and Python 3 for the tests. Without
  `JASMINC` the build checks `gen/` against the manifest and the Jasmin
  sources before using it. With `JASMINC` it compiles the sources as before;
  `make gen` regenerates `gen/` and CI fails when it differs from the
  pinned compiler's output.
