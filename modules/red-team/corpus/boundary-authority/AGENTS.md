# Phase 18 boundary corpus

Matched vulnerable and safe applications exercise lab-private DNS, HTTP callback/redirect/proxy,
TLS trust and connection state, local privilege policy, and delegated authority. The Peritus host
owns every protocol peer and the copied applications receive only `/work` Unix-socket paths.

`shared-service.py` is the common application behavior. The two `application.py` launchers select
only the vulnerable or safe policy. Do not add internet, host-loopback, LAN, cloud credentials, or
host privilege to this corpus.
