# Peritus Module Market

The official catalog of installable Peritus workflow modules. Each module is an
independently versioned package under `modules/`; `market.toml` is the discovery index.
Peritus can browse cached entries, install a pinned package, enable it and select it
from **Module market** in the TUI or GUI (`/modules`).

## Available modules

| Module | Purpose |
| --- | --- |
| [Deep Research](modules/deep-research/README.md) | Approve a plan, gather original sources, assess them with a skeptic, synthesize admitted evidence and independently fact-check the report. |

Requires a Peritus build with the module-market and `research-v1` host capabilities.
The initial implementation is on Project-Peritus's `develop` branch; older releases
do not acquire these host features merely by downloading this repository.

## Using the market

Open `/modules`, refresh, select a module and install it. New installs and updates
start disabled. Enable the selected version, then **Use module**. In the terminal,
use arrow keys, `i` to install, `e` to enable and Enter to select. `r` refreshes.

Scriptable management:

```sh
peritus modules refresh
peritus modules market
peritus modules install-market peritus.deep-research DIGEST_FROM_CATALOG
peritus modules enable peritus.deep-research
```

Peritus resolves `main` to a Git commit and fetches only that commit's catalog,
manifest and declared resources over HTTPS. Package digests bind their exact bytes.
No Git executable, paid API, container, install script or separate account is required.
Cached discovery and already installed modules remain usable when GitHub is unavailable.
Updates are explicit; running jobs remain pinned to their original package identity.

## Adding modules

1. Copy [the workflow template](templates/workflow/module.toml) into a unique
   `modules/YOUR-MODULE/` folder. Change its stable ID, version and instructions.
2. Include only the manifest and declared read resources. Document scope, required
   tools, lifecycle and actual-interface acceptance in the module README.
3. Install that local folder with `peritus modules install DIRECTORY`. Its JSON
   result gives the canonical package digest. Use isolated application data while
   developing so it does not replace your normal selection.
4. Add a `[[modules]]` entry to `market.toml`, with matching ID, name, version,
   description, relative path and digest, plus optional discovery tags.
5. Exercise the workflow through real Peritus interfaces and retain a small failure
   replay if a defect is found. Submit the package and catalog change together.

See [the catalog contract](CATALOG.md). Add as many independent modules as needed;
adding one does not require rebuilding Peritus unless it needs a new host capability.
Ordinary workflow packages cannot add executable code, new tools or permissions.

## Trust and permissions

Catalog inclusion and digest integrity establish origin/identity, not correctness.
Read a module's purpose and capabilities before enabling it. Package prompts remain
subordinate to user instructions and host policy. Peritus owns credentials, model
routing, tools, cancellation, evidence and durable job state. Enabling a module never
widens the current workspace's tool permissions.
