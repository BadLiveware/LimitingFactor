# LimitingFactor.Native

Packages the native Linux namespace and mount helper used by `LimitingFactor.LowLevel`.

The helper is built from project-owned source during the managed build and included as a RID-specific native asset. It is invoked directly—never through a command shell—and removes the runtime dependency on Bubblewrap and `fusermount3`. Its command protocol is intentionally private to the low-level package.

Most applications should use `LimitingFactor`. Use `LimitingFactor.LowLevel` when explicit mount and process-launch primitives are required.
