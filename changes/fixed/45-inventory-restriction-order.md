- `make -C proofs check-inventory` no longer depends on the host. EasyCrypt
  can print the members of a memory restriction, such as `Adv{-A, -B}`, in
  a different order on different machines for the same theories; the
  inventory now sorts them, so it records the set and not the print order.
