# Tests

Offline unit tests for the reconciliation engine. **No dependencies** beyond the
Python 3 standard library — no Salt install, no `librouteros`, no real router.

## Why this works

The engine (`_modules/mikrotik.py`) is pure Python. Its only coupling to the
device is the `__proxy__` dunder it calls for I/O
(`mikrotik.path/add/update/remove/fresh_ping`). The tests:

1. load the module straight from its file (`tests/harness.py:load_engine`,
   bypassing Salt's loader), then
2. inject `module.__proxy__` = an in-memory `FakeDevice`.

`FakeDevice` faithfully models RouterOS ordering: `add` honors a
`place-before=<.id>` directive (insert before that row, else append) and assigns
`.id`s on insert, so **rule order after an apply is a real, assertable fact**.

## Run

```sh
python3 -m unittest discover -s tests -v
```

(or a single class: `python3 -m unittest tests.test_ordered.TestPlaceBefore -v`)

## What is covered

`tests/test_ordered.py`:

- **Regression** — desired-mirrors-device is zero-diff; untagged hand-written
  rules stay invisible even under `purge=True`; comment-tag helpers round-trip.
- **`place_before`** — a new rule resolves its anchor `.id` at plan time and
  inserts immediately before it; the directive never leaks into a device write
  or a false diff; inserts are idempotent and never emit a move; multiple new
  rules anchored to the same rule keep pillar order; a missing anchor is a hard
  error; `place_after` is rejected; `place_before` on a collection is rejected.
- **Rollback safety** — the inverse of an insert is a position-independent
  `remove [find comment~"[salt:<tag>]"]` (never a `move`/`place-before`);
  `commit_confirm` arms that revert script before inserting.
- **Cleanup scenario** — the real workflow: in one apply, `purge` a dead tagged
  rule *and* insert a new rule before the catch-all drop, leaving the untagged
  hand-written rule untouched.

## The two-layer test process

1. **Offline (this suite)** — fast, runs anywhere, gates every engine change.
2. **On-device (salt-01)** — the final gate against a real RouterOS box:
   ```sh
   salt-sproxy --sync-all <device> state.apply mikrotik.firewall test=True
   ```
   Always dry-run first; firewall applies carry `confirm_timeout` (commit-confirm
   auto-revert). See the top-level `README.rst`.
