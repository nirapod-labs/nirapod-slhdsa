# A Tight Security Proof for SPHINCS⁺, Formally Verified
This repository accompanies the paper "A Tight Security Proof for SPHINCS⁺, Formally Verified", authored by Manuel Barbosa, François Dupressoir, Andreas Hülsing, Matthias Meijers, and Pierre-Yves Strub.
The most recent version of the paper can be found [here](https://eprint.iacr.org/2024/910).\
\
This repository comprises EasyCrypt scripts primarly aimed at the formal verification of the security of SPHINCS⁺, effectively verifying a modular version of the proof presented in
[Recovering the Tight Security Proof of SPHINCS⁺](https://link.springer.com/chapter/10.1007/978-3-031-22972-5_1).
Due to the module approach, we are able to reuse some of the artifacts produced in [the formal verification of XMSS](https://github.com/MM45/FV-XMSS-EC).
Furthermore, this repository contains several generic, reusable libraries (employed in the development) that are either novel or improvements over previous libararies.
