# Optional applications

This directory is reserved for first-party interfaces that are useful to the
research workflow but are not part of the core Python package. Every app must
have its own README, lockfile, test/build command, and explicit data contract.

Applications may expose only sanitized status or aggregate data. They must not
embed raw run output, credentials, local paths, hosting state, or build
artifacts. API locations, run roots, schemas, and allowed origins must be
explicitly configured and validated.

The historical RQ2 live monitor remains local until its hard-coded API/run
schema, permissive CORS, error forwarding, result exposure, and local hosting
configuration are removed and its source can pass the repository audit and a
fresh dependency-locked build. It is not considered cloud-backed yet.
