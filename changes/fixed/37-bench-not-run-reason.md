- `bench/render.py` gives each row that was not run the reason the
  benchmark program reported for it. BoringSSL's deterministic signing at
  more than one thread was labelled "keeps state between calls"; it is now
  "not offered", since BoringSSL's public API does not provide that mode.
