Changelog
=========

All notable changes to this formula are documented here. This project adheres
to `Semantic Versioning <https://semver.org/>`_.

0.0.2
-----

Added
~~~~~

- ``place_before: <tag>`` on ordered firewall rules (filter/nat/raw). A new rule
  can be inserted immediately before an existing managed (tagged) rule; the
  anchor is resolved to its live ``.id`` and passed to RouterOS ``add``. Honored
  **only on insert** -- an existing rule is never moved, so applies stay
  idempotent and the commit-confirm rollback stays valid (the inverse of an
  insert is a position-independent remove). ``place_after`` is rejected (no
  native RouterOS equivalent); a missing anchor, and ``place_before`` on a
  non-ordered path, are hard errors.
- Offline test suite under ``tests/`` -- stdlib ``unittest`` with an in-memory
  ``FakeDevice`` that models ``place-before`` ordering, so the engine is testable
  with no Salt, no ``librouteros`` and no device::

      python3 -m unittest discover -s tests -v

0.0.1
-----

Initial public release. Extracted from a private Salt tree where it managed a
MikroTik hEX S edge router agentlessly via salt-sproxy.

Added
~~~~~

- ``_proxy/mikrotik.py`` -- librouteros API connection, ``path()`` getter and
  post-init device ``grains()``.
- ``_modules/mikrotik.py`` -- schema-driven reconciliation engine. Per-path
  ``_SCHEMA`` (shape ``singleton`` | ``collection`` | ``ordered``, primary keys,
  field defaults, computed flags). Default/computed-aware diffing to suppress
  false diffs; dynamic/builtin rows protected; opt-in ``purge`` with ``restrict``
  scoping. ``commit_confirm`` arms a router-side inverse-diff scheduler
  (dead-man's switch) that auto-reverts unless reachability is reconfirmed.
  ``adopt`` one-time bootstrap for ordered paths.
- ``_states/mikrotik.py`` -- ``mikrotik.collection`` and ``mikrotik.singleton``
  with full ``test=True`` support.
- ``mikrotik/`` states rendering ``/ip/address``, ``/ip/dns/static``, a set of
  generic keyed collections, system singletons, and the firewall paths
  (``address-list`` plus the ordered ``filter`` / ``nat`` / ``raw``).
- ``ordered`` shape: ``[salt:<tag>]`` comment-tag identity for paths with no
  natural key. Only tagged rows are managed; untagged hand-written rules are
  never matched, updated or purged. Rule content is managed; order is left as-is.

Notes
~~~~~

- Reconciliation design derived from the GPL-3.0-or-later community.routeros
  Ansible collection.
- Reordering is intentionally out of scope: RouterOS ``move`` cannot be undone
  by the commit-confirm rollback.
