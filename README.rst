===============
mikrotik-formula
===============

.. warning::

   **AI-authored, early-stage, no warranty.** This formula was written almost
   entirely by an AI coding agent (Anthropic's Claude). It is in **early
   development (0.0.x)**, has had limited real-world exposure, and its
   interfaces may change without notice. It can and will touch firewall and
   routing configuration on a live device, which carries a real risk of
   lockout or outage.

   Review the code yourself, always dry-run with ``test=True`` first, use the
   ``confirm_timeout`` (commit-confirm) safety net on firewall changes, and
   test against a non-production device before trusting it. **Provided "AS IS",
   WITHOUT WARRANTY OF ANY KIND** (see the GNU GPL v3, sections 15-16, in
   ``LICENSE``). You use it entirely at your own risk.

Agentless, schema-driven configuration management for MikroTik RouterOS,
driven from a Salt master via `salt-sproxy`_ -- no agent and no proxy daemon
on the device.

.. _salt-sproxy: https://salt-sproxy.readthedocs.io/

The formula ships:

- ``_proxy/mikrotik.py`` -- a ``librouteros`` API connection, a ``path()``
  getter and device ``grains()``.
- ``_modules/mikrotik.py`` -- a schema-driven reconciliation engine.
- ``_states/mikrotik.py`` -- ``mikrotik.collection`` and ``mikrotik.singleton``
  states with full ``test=True`` support.
- ``mikrotik/`` -- thin SLS that render desired state from pillar.

The reconciliation design is derived from the `community.routeros`_ Ansible
collection and is therefore licensed **GPL-3.0-or-later** (see ``LICENSE``).

.. _community.routeros: https://github.com/ansible-collections/community.routeros

.. contents:: **Table of Contents**
   :depth: 2


Requirements
============

- A Salt master (3006+).
- ``salt-sproxy`` installed on the master.
- ``librouteros`` available to the Salt Python environment (for onedir
  installs, ``salt-pip install librouteros``).
- A RouterOS device with the API service enabled and a dedicated user. A
  least-privilege group (e.g. ``api,read,write,test`` -- no ``policy``, no
  ``sensitive``) is sufficient, including for the commit-confirm scheduler.
  The read-only/limited user cannot read ``sensitive`` fields (private keys,
  secrets); the formula never manages those.


Installation
============

This formula ships custom execution/state/proxy modules in the ``_modules/``,
``_states/`` and ``_proxy/`` directories at the repository root. For Salt to
sync them they must land at the **root of a fileserver environment**, which is
the default when the repo root is served.

gitfs (recommended -- "use it from source")
--------------------------------------------

Add the repo as a gitfs remote on the master and pin a tag::

    gitfs_remotes:
      - https://github.com/tuxillo/mikrotik-formula:
          - base: v0.0.1

gitfs merges the repo root into the environment, so ``salt://mikrotik/...`` and
``salt://_modules/mikrotik.py`` (and ``_states``/``_proxy``) become available.

file_roots (vendored)
---------------------

Clone the repo and add its root to ``file_roots``::

    file_roots:
      base:
        - /srv/salt
        - /srv/formulas/mikrotik-formula


Syncing the modules  (IMPORTANT for salt-sproxy)
================================================

With ``salt-sproxy`` you MUST sync the dynamic modules **in-context** with
``--sync-all`` on the run itself::

    salt-sproxy --sync-all <device> state.apply mikrotik test=True

The master-side runners (``salt-run saltutil.sync_modules`` etc.) do **not**
populate salt-sproxy's execution-module context, and you will get
``KeyError: 'mikrotik.<func>'``. Editing the *proxy* module is the exception:
``salt-run saltutil.sync_proxymodules`` works for it.


Configuration
=============

See ``pillar.example.yaml``. Two independent pillar blocks are involved:

``proxy:``
    Connection details consumed by the proxy module. The host pillar that
    carries this block must use plain ``#!yaml`` (NOT ``#!yamlex`` -- salt-sproxy
    fails its proxytype membership check on yamlex scalars). Encrypt the
    password with the nacl renderer.

``mikrotik:``
    Desired-state data rendered by the states. Seed each path as an exact
    mirror of the live device so the first ``test=True`` shows zero diff, then
    evolve. ``purge: false`` is the safe additive default.

Path shapes
-----------

singleton
    A single-value path (e.g. ``/system/identity``). ``mikrotik.singleton``.

collection
    A natural-key path (e.g. ``/ip/address`` keyed by ``address+interface``).
    ``mikrotik.collection``. Dynamic/builtin rows are protected; ``restrict``
    scopes matching and purge to a subset of rows.

ordered
    A path with **no natural key** (``/ip/firewall/{filter,nat,raw}``).
    Identity is an embedded ``[salt:<tag>]`` comment. **Only tagged rows are
    managed; untagged hand-written rules are never matched, updated or
    purged** -- this is the ownership boundary. The engine manages rule
    *content* only; rule *order* is left as-is (adopted rules keep their
    position, new rules append). Reordering is intentionally out of scope:
    RouterOS ``move`` cannot be undone by the rollback.


Bootstrapping an existing device
=================================

Ordered firewall paths must be **adopted** once before they can be managed:
``mikrotik.adopt`` writes the ``[salt:<tag>]`` comment onto each existing
untagged rule and emits paste-ready pillar. Do NAT first (it is not the lockout
path); do the ``input`` chain last.

::

    # 1. Preview the tags + pillar it would emit (no device change):
    salt-sproxy --sync-all <device> mikrotik.adopt '[ip,firewall,nat]' dry_run=True

    # 2. Write the tags onto the live rules:
    salt-sproxy --sync-all <device> mikrotik.adopt '[ip,firewall,nat]' dry_run=False

    # 3. Paste the emitted `rules:` into pillar, then confirm zero diff:
    salt-sproxy --sync-all <device> state.apply mikrotik.firewall test=True

.. warning::

   Adopt (``dry_run=False``, writes tags) MUST run before the zero-diff gate.
   If you seed pillar and apply while the live rules are still untagged, the
   engine cannot see them and plans to **add** the tagged copies -- a real
   apply would create DUPLICATES. An ``add`` in a test run is the tell-tale
   that the tag-write step was skipped. ``dry_run`` (adopt arg) is separate
   from ``test`` (Salt state mode).


Commit-confirm (lockout safety net)
===================================

Any ``mikrotik.collection`` call may set ``confirm_timeout`` (minutes). The
engine then arms a router-side ``/system/scheduler`` whose ``on-event`` is an
inverse-diff script (a dead-man's switch), applies the change, verifies
reachability over a **new** API connection, and either confirms (disarms) or
lets the device auto-revert. Always set ``confirm_timeout`` on firewall paths,
and touch the ``input`` chain (the master's lifeline to the device API) last
and ``restrict``-scoped.


Usage
=====

Dry-run the whole device, then apply::

    salt-sproxy --sync-all <device> state.apply mikrotik test=True
    salt-sproxy --sync-all <device> state.apply mikrotik

Proxy minions are deliberately NOT wired into a global ``'*'`` highstate -- the
formula's states target the device, not the host the proxy runs on. Apply
``mikrotik`` explicitly.


Available states
================

``mikrotik``
    Roll-up; includes all of the below.
``mikrotik.system``
    Singleton paths from ``mikrotik:singletons``.
``mikrotik.addresses``
    ``/ip/address`` from ``mikrotik:ip_address``.
``mikrotik.dns``
    ``/ip/dns/static`` from ``mikrotik:dns_static``.
``mikrotik.collections``
    Generic keyed collections from ``mikrotik:collections``.
``mikrotik.firewall``
    ``/ip/firewall/address-list`` and the ordered ``filter``/``nat``/``raw``
    from ``mikrotik:firewall``.


License
=======

GPL-3.0-or-later. Copyright (c) 2026 Antonio Huete Jimenez. Reconciliation
design derived from the community.routeros Ansible collection (Copyright (c)
Ansible Project, GPL-3.0-or-later).
