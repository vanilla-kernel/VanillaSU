# Multi Valid Managers Design

## Goal

Allow the kernel to recognize multiple valid manager app IDs while preserving the existing userspace contract that exposes a single primary manager app ID.

## Current Behavior

The manager identity layer stores one global `ksu_manager_appid`. The package scanner stops after the first valid manager APK found under `/data/app`, and all permission checks compare the caller app ID against that one value.

## Design

Keep `GET_MANAGER_APPID` compatible by returning the primary manager app ID. Internally replace the single app ID check with a small fixed-size set of valid manager app IDs. The first entry in the set is the primary manager for legacy callers.

The automatic throne tracker will rebuild the manager set from `/data/system/packages.list` and `/data/app` during full rescans. It will continue scanning after a valid manager APK is found, collect every matching app ID in a local fixed-size buffer, avoid duplicate entries, and replace the global manager set after the scan completes.

The manual `CHANGE_MANAGER_UID` path remains a root-only compatibility path. It will set the primary manager app ID and reset the internal set to exactly that one app ID.

## Interfaces

- `ksu_get_manager_appid()` returns the primary manager app ID or `KSU_INVALID_APPID`.
- `ksu_set_manager_appid(appid)` resets the internal set to one primary app ID.
- `ksu_add_manager_appid(appid)` adds another valid manager app ID if capacity permits.
- `ksu_replace_manager_appids(appids, count)` replaces the internal set after scanner rebuilds.
- `is_manager()` and `is_uid_manager(uid)` return true for any app ID in the set.

## Constraints

- Do not add a new UAPI in this change.
- Keep `CONFIG_KSU_DISABLE_MANAGER` behavior unchanged.
- Keep memory management simple: use a fixed-size in-kernel array, not heap allocation.
- Keep manager APK validation based on the existing signature/package checks.

## Testing

Compile-check the modified manager and supercall code where possible. Use grep-based checks to confirm all direct `ksu_manager_appid` users are converted to the new helper API.
