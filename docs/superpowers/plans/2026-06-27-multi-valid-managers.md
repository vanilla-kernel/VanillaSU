# Multi Valid Managers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow several valid KernelSU manager app IDs inside the kernel while preserving the legacy primary manager app ID API.

**Architecture:** Store manager app IDs in a fixed-size identity set with the first entry treated as the primary app ID. Update the throne tracker to rebuild the set from every valid manager APK it finds, while root-only manual override still resets the set to one app ID.

**Tech Stack:** Linux kernel C, KernelSU manager identity helpers, existing supercall UAPI.

## Global Constraints

- Do not add a new UAPI.
- Preserve `GET_MANAGER_APPID` as primary-manager-only compatibility behavior.
- Keep `CONFIG_KSU_DISABLE_MANAGER` behavior unchanged.
- Use fixed-size kernel storage, not dynamic allocation, for manager app IDs.
- Commit each task separately.

---

### Task 1: Manager Identity Set

**Files:**
- Modify: `kernel/manager/manager_identity.h`
- Modify: `kernel/manager/throne_tracker.c`

**Interfaces:**
- Produces: `ksu_manager_appids[]`, `ksu_manager_appid_count`, `ksu_get_manager_appid()`, `ksu_set_manager_appid(uid_t appid)`, `ksu_add_manager_appid(uid_t appid)`, `ksu_clear_manager_appids()`, `is_manager()`, `is_uid_manager(uid_t uid)`.
- Consumes: Existing users of `ksu_get_manager_appid()`, `ksu_set_manager_appid()`, `is_manager()`, and `is_uid_manager()`.

- [ ] Replace the single global manager app ID with fixed-size app ID storage.
- [ ] Update helper functions to check every stored app ID.
- [ ] Preserve disabled-manager inline behavior.
- [ ] Compile-check changed files.
- [ ] Commit as `feat: store multiple manager appids`.

### Task 2: Throne Tracker Multi-Scan

**Files:**
- Modify: `kernel/manager/throne_tracker.c`

**Interfaces:**
- Consumes: `ksu_clear_manager_appids()`, `ksu_add_manager_appid(uid_t appid)`, `ksu_is_manager_appid_valid()`.
- Produces: Scanner behavior that adds every valid manager app ID found under `/data/app`.

- [ ] Update `crown_manager()` to add matching package app IDs instead of replacing one global value.
- [ ] Update directory scanning to continue after valid manager APKs are found.
- [ ] Rebuild the app ID set during full scans and keep prune-only behavior unchanged.
- [ ] Compile-check changed files.
- [ ] Commit as `feat: detect all valid manager apks`.

### Task 3: Compatibility Checks

**Files:**
- Modify: `kernel/manager/apk_sign.c`
- Modify: `kernel/supercall/supercall.c`
- Review: `kernel/supercall/dispatch.c`, `kernel/supercall/perm.c`, `kernel/policy/allowlist.c`, `kernel/hook/setuid_hook.c`

**Interfaces:**
- Consumes: New manager identity helpers.
- Produces: Manual override and debug override that reset the primary manager app ID and leave compatibility callers unchanged.

- [ ] Ensure root-only `CHANGE_MANAGER_UID` still sets one primary manager app ID.
- [ ] Ensure debug manager app ID override still sets one primary manager app ID.
- [ ] Confirm all permission paths use `is_manager()` or `is_uid_manager()`.
- [ ] Run grep-based validation and compile-check changed files.
- [ ] Commit as `test: verify manager identity compatibility`.
