- The hash layer's memory loops address their input and output as a fixed
  base plus an offset, and the HMAC key-block functions zero `K0` at
  constant indices before writing it, the forms `jasmin-checksafety` needs
  to relate each access to its buffer and to see `K0` initialised. Outputs
  are unchanged.
