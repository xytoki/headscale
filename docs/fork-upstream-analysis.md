# Fork vs upstream analysis (`xytoki/headscale` vs `juanfont/headscale`)

_Date: 2026-02-13_

## Scope and baseline

- Compared `origin/main` (this fork) against `upstream/main`.
- Fork point (merge-base): `5e74ca94` (`Fix IPv6 in ACLs (#1339)`, 2023-04-16).
- Divergence at analysis time:
  - fork-only commits: **10**
  - upstream-only commits: **980**

## What this fork added after forking

Fork-only commits are concentrated in three runtime files (`machine.go`, `api_common.go`, `config.go`) plus one CI tweak.

### Functional changes in fork

1. **Endpoint local-range filtering** (`machine.go`)
   - Added `isLocalRange` + `removeLocalRange`.
   - Behavior: remove peer endpoints that are inside configured tailnet IP prefixes.

2. **Tag-based peer isolation for direct connectivity** (`machine.go`)
   - Added `isIsolatedPeer` and `removeEndpointForIsolatePeer`.
   - Behavior: for tags prefixed `tag:isolated-*`, keep peer in map but clear endpoints so direct path is prevented and DERP path is favored.

3. **Per-node DERP region filtering/fallback via tags** (`api_common.go`)
   - Added `getDERPMapByMachine` and `filterPeerDERP`.
   - Behavior:
     - `tag:ignore-derp-<region>` removes DERP regions from node view.
     - `tag:fallback-derp-<region>` rewrites filtered peer DERP to fallback region.
     - Forces `Debug.DERPRoute = "true"`.

4. **Disable automatic split-DNS search-domain injection** (`config.go`)
   - Commented out `domains = append(domains, domain)`.
   - Behavior: split-DNS domains are no longer automatically added to search domains.

5. **Non-runtime changes**
   - One release workflow tweak and one lint/style follow-up commit.

## What upstream implemented after forking

Upstream moved from the fork’s state (`0.22.0` line) to current releases through `0.28.x` and `0.29.0` development.

Observed indicators:

- `origin/main` CHANGELOG ends at `0.22.0 (2023-XX-XX)`.
- `upstream/main` includes `0.22.1` .. `0.28.0` and `0.29.0` section.
- Upstream introduced major structural changes (new top-level `hscontrol/` and related packages).

High-level upstream advances since fork include:

- substantial architecture refactor (`hscontrol/*` split and modernization)
- ongoing policy/ACL compatibility work and tests
- many releases with bug fixes, security/dependency updates, CI/process improvements
- DNS/DERP configuration evolution (including explicit `dns.search_domains` support)

## Conflicts when porting fork commits to latest upstream

A direct cherry-pick test of fork functional commits onto `upstream/main` shows **hard conflicts**.

### Conflict result summary

- Commits touching `machine.go` conflict with **modify/delete** (`machine.go` removed in upstream layout).
- Commits touching `api_common.go` conflict with **modify/delete** (`api_common.go` removed in upstream layout).
- Commit touching `config.go` conflicts with **modify/delete** (`config.go` removed in upstream layout).

So porting is not a clean cherry-pick; each behavior must be reimplemented against new upstream architecture.

## Are fork-added functions still needed to port?

### Likely **not needed** as-is

- **No-more-search-domains patch**: upstream already has explicit `dns.search_domains` handling (`hscontrol/types/config.go`), so the old patch is functionally superseded.

### Potentially still useful, but needs redesign

- **Local-range endpoint filtering**
- **Tag-based direct-path isolation**
- **Per-node DERP ignore/fallback tags**

These are deployment-specific behaviors not present upstream under the same tag semantics. If still required operationally, they should be reintroduced as configurable features in upstream’s current `hscontrol` model, not by replaying old commits.

## Practical recommendation

1. Rebase strategy: **do not cherry-pick old fork commits directly**.
2. Start from latest upstream and re-spec only the behaviors you still need:
   - define required semantics in config/policy terms
   - implement in current `hscontrol` paths
   - add tests around each behavior
3. Drop obsolete fork patch (`no more search domains`) in favor of upstream config (`dns.search_domains`).
