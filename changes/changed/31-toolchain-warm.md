- A daily CI run on `main` builds and stores the toolchain for new runner
  images, so pull requests rarely rebuild it after an image update. A run
  that has to build it logs which parts of the runner's host identity
  changed.
