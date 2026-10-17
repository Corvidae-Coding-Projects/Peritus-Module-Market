# Catalog contract, schema 1

`market.toml` has `schema = 1`, a plain-text `name`, and zero or more `[[modules]]`
entries. Each entry has `id`, `name`, numeric `major.minor.patch` `version`, plain-text
`description`, repository-relative `path`, canonical lowercase SHA-256 package
`digest`, and optional `tags` (plain-text strings). IDs and paths must be unique.
Paths use safe alphanumeric, dash, underscore and dot components; no absolute paths,
traversal, symlinks or URL escaping. The selected path contains `module.toml`.

Package format: `schema=1`, stable `id`, numeric `version`, `name`, `description`,
`roles`, `stages`, optional `resources` and optional host `workflow` contract.
Roles declare unique `id`, `model=writer|reviewer`, `instructions` and exact `tools`.
Stages declare unique `id`, role and only earlier-stage `inputs`. Resources are
explicitly listed regular files; undeclared files and README/AGENTS navigation do
not enter the package. `research-v1` is a host-enforced contract with five specific
stages, typed evidence and human plan approval; ordinary packages omit it.

The host computes the canonical digest; do not use the hash of the TOML file.
It covers the canonical parsed manifest, sorted resource names, lengths and bytes.
Editing any packaged instruction/resource changes the digest. Bump the version and
update the catalog together. Git history retains earlier versions; installations
record their repository commit, package path and digest. A digest selected in a
menu must still match the cached entry at install time; stale selections are rejected.

The default host fetches this repository's `main` branch using the GitHub ref API,
then uses immutable raw URLs for that commit. Each transfer has a deadline and byte
bound, and packages stage fully before registry publication. Errors preserve the
previous catalog/selection. These checks do not authenticate publisher intent beyond
the configured HTTPS repository; no claim of signed releases is made.
