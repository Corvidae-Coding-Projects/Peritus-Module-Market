# Boundary, protocol, TLS, policy, and authority twins

These matched applications back the Phase 18 `peritus.boundary-authority` campaign. Both run inside
the ordinary copied HTTP laboratory. During a campaign the host creates short-lived Unix-socket
DNS, callback/redirect/proxy, and TLS peers in the private laboratory directory. The target can
reach those peers but has no general network route.

The vulnerable twin accepts forbidden destination inputs far enough to emit a blind private
callback, disables certificate checks for hostname/expiry cases, accepts plaintext downgrade,
declares root-style local policy, and lets untrusted prompt/plugin data invoke a privileged copied
application action. The safe twin rejects those operations while retaining legitimate private-peer,
trusted-TLS, contained-privilege, and scoped delegation behavior.

Neither twin can reach public, LAN, or host-loopback services or acquire host authority.
