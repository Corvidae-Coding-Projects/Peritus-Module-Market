# Safe file/parser twin

`application.py` supervises the copied HTTP service. `service.py` implements the same legitimate
contract while rejecting traversal, symlink, archive, malformed-input, and native-fault probes.

[Parent map](../AGENTS.md).
