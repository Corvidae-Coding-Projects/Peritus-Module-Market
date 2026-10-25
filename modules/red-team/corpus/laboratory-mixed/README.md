# Disposable multi-service laboratory fixture

This Phase 11 fixture is a real copied application process plus a copied backing-service process.
The application accepts bounded JSON over standard input and reaches the store through a Unix socket
inside its private filesystem. At readiness it also attempts to read a host file, observe common
credential variables, connect to a host-loopback canary and execute an unregistered descendant. The
host receipt distinguishes target-reported facts from independently enforced sandbox and canary
observations.

The fixture is intentionally small. It validates the laboratory lifecycle and containment boundary;
it does not imply that arbitrary application build recipes are supported yet.

`application-leak.py` is a hostile control: it tries to print target-only secret bytes during
readiness. A conforming host must detect the disclosure, terminate the complete process tree, and
quarantine the laboratory without returning those bytes to the module.
