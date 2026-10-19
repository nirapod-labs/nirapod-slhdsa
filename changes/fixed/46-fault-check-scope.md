- The documentation of the fault check (`docs/API.md`, `docs/SECURITY-MODEL.md`)
  no longer says that it stops the published fault attacks on SPHINCS+
  signing. Verifying each signature before release withholds only faulty
  signatures that do not verify, from a fault on the path from the signed leaf
  to a tree's root. A fault in an authentication path, or in the subtree below
  one, gives a signature that verifies and can still be used for a forgery;
  the check returns it, and by the published analysis this is the outcome of
  most random faults. The library's behaviour is unchanged.
