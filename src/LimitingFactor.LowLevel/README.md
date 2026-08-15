# LimitingFactor.LowLevel

Resource-safe process-sandbox mechanisms for Linux on x86-64.

The package launches the RID-specific helper supplied by `LimitingFactor.Native`, owns its process and control channel, runs FUSE approval filesystems against helper-mounted descriptors, and manages OverlayFS copy-on-write state. It has no runtime dependency on `bwrap`, `fusermount3`, or a command shell.

Callers provide explicit mount and launch specifications and own policy validation. Use `LimitingFactor` for validated grants, approval requests, ergonomic process startup, and COW apply/discard sessions.
