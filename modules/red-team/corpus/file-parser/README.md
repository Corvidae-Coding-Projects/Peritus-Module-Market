# File, archive, parser, and native-fault twins

These source fixtures are launched only in a module-owned target runtime inside a disposable Linux worker. Both twins
support ordinary file upload, TAR extraction, and the small `PH16` length-prefixed grammar. The
vulnerable twin also demonstrates path traversal, symbolic-link following, predictable temporary
files, permission changes, archive traversal, malformed-parser failure, and a child-only native
fault. The safe twin rejects those hostile inputs while remaining available for later requests.

The module never treats a fixture's own success text as proof. Project Peritus owns fixed canary
paths, observes process signals and state, bounds every request, and retains exact minimized inputs.
