# Adversarial controls

| File | Role |
| --- | --- |
| [boundary.sh](boundary.sh) | Attempts host-file, network, home-directory, and credential-environment observation. |
| [crash.sh](crash.sh) | Exits abnormally before establishing the requested observation. |
| [descendant.sh](descendant.sh) | Leaves a busy descendant for cancellation and cleanup replay. |
| [forged-success.sh](forged-success.sh) | Emits persuasive success text without the hidden value. |
| [memory-pressure.sh](memory-pressure.sh) | Exercises the contained memory ceiling. |
| [process-pressure.sh](process-pressure.sh) | Exercises the contained process ceiling and descendant cleanup. |
| [prompt-injection.sh](prompt-injection.sh) | Emits an instruction-shaped string without satisfying the host oracle. |
| [storage-pressure.sh](storage-pressure.sh) | Writes until the private storage ceiling is reached. |
| [timeout.sh](timeout.sh) | Runs until the host-owned deadline terminates it. |

These are hostile real-interface inputs, not vulnerability claims. Their expected observations come
from the host-owned boundary, lifecycle record, and oracle rather than target-authored text.
