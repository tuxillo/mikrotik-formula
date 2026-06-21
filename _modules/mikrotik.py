# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# The schema-driven reconciliation design (per-path shapes, primary keys,
# field defaults to suppress false diffs, filtering dynamic/builtin rows,
# opt-in purge with restrict) is derived from the community.routeros Ansible
# collection:
#   Copyright (c) Ansible Project -- GPL-3.0-or-later
#   https://github.com/ansible-collections/community.routeros
"""
Execution module for MikroTik RouterOS proxy minions.

Besides thin read wrappers (``path``/``facts``), this module provides a
schema-driven config-management engine that reconciles desired state (from
pillar) against the live device over the RouterOS API.

Each managed path is described by a small entry in ``_SCHEMA`` and classified
into one *shape*:

* ``singleton``  -- exactly one settable record (e.g. /system/identity)
* ``collection`` -- many rows identified by a natural ``primary_keys`` tuple
                    (e.g. /ip/address keyed by (address, interface))
* ``ordered``    -- rows with no natural key (e.g. /ip/firewall/filter), matched
                    by an embedded ``[salt:<tag>]`` comment. Only tagged rows are
                    managed; untagged rows are invisible. Rule *content* is
                    reconciled; rule *order* is left as-is.

The engine reads live state, drops dynamic/builtin rows, matches desired to
live (by primary key, or by comment tag for ordered paths), suppresses false
diffs using per-field ``default`` and ``computed`` metadata, and (unless
``test=True``) applies add/update/remove. Purging of unmanaged rows is opt-in
per call and can be scoped with ``restrict``.
"""

import re

__proxyenabled__ = ["mikrotik"]
__virtualname__ = "mikrotik"

# Keys allowed in a desired entry that are engine directives, not device fields:
# the comment-tag identity and the placement anchor. Stripped before any write
# or diff so they never reach RouterOS or register as a false change.
_RESERVED = ("tag", "place_before", "place_after")


# ---------------------------------------------------------------------------
# Firewall field maps (shared by /ip/firewall/{filter,nat,raw}, all "ordered").
# These paths have NO natural key -- identity is position + content -- so they
# are managed by an embedded comment tag (see the "ordered" shape below). We
# enumerate the fields we manage so `_writable` (used for purge re-adds and the
# inverse-revert script) captures full rule content and never re-adds runtime
# counters (bytes/packets) the API also returns.
# ---------------------------------------------------------------------------
_FW_COMMON_FIELDS = {
    "chain": {},
    "action": {},
    "comment": {"can_disable": True, "remove_value": ""},
    "disabled": {"default": False},
    "log": {"default": False},
    "log-prefix": {},
    "protocol": {},
    "src-address": {},
    "dst-address": {},
    "src-address-list": {},
    "dst-address-list": {},
    "src-port": {},
    "dst-port": {},
    "in-interface": {},
    "out-interface": {},
    "in-interface-list": {},
    "out-interface-list": {},
    "connection-state": {},
    "connection-nat-state": {},
    "connection-limit": {},
    "connection-mark": {},
    "limit": {},
    "ipsec-policy": {},
}


def _fw_fields(*extra):
    fields = dict(_FW_COMMON_FIELDS)
    for block in extra:
        fields.update(block)
    return fields


# ---------------------------------------------------------------------------
# Per-path schema. Keep this small: only describe paths we actually manage.
# field metadata keys:
#   default   -- RouterOS default; if device omits the field and desired equals
#                this, it is not a diff.
#   computed  -- value derived by the device (never diffed, never written).
#   can_disable / remove_value -- field can be unset; remove_value is what the
#                device shows when unset (informational for now).
# ---------------------------------------------------------------------------
_SCHEMA = {
    ("ip", "address"): {
        "shape": "collection",
        "primary_keys": ("address", "interface"),
        "fields": {
            "address": {},
            "interface": {},
            "disabled": {"default": False},
            "comment": {"can_disable": True, "remove_value": ""},
            "network": {"computed": True},
        },
    },
    ("ip", "dns"): {
        "shape": "singleton",
        "fields": {},
    },
    ("ip", "route"): {
        "shape": "collection",
        # Static routes only; the many connected/dhcp routes are dynamic=true and
        # filtered out. Identity = destination + gateway.
        "primary_keys": ("dst-address", "gateway"),
        "fields": {
            "dst-address": {},
            "gateway": {},
            "distance": {"default": 1},
            "routing-table": {"default": "main"},
            "disabled": {"default": False},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("ip", "pool"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "ranges": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "vlan"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "interface": {},
            "vlan-id": {},
            "disabled": {"default": False},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "list"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "list", "member"): {
        "shape": "collection",
        "primary_keys": ("interface", "list"),
        "fields": {
            "interface": {},
            "list": {},
            "comment": {"can_disable": True, "remove_value": ""},
            "disabled": {"default": False},
        },
    },
    ("snmp", "community"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "addresses": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("ip", "dhcp-server", "network"): {
        "shape": "collection",
        "primary_keys": ("address",),
        "fields": {
            "address": {},
            "gateway": {},
            "domain": {},
            "dns-server": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("ip", "dhcp-server"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "address-pool": {},
            "interface": {},
            "lease-time": {},
            "lease-script": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "bridge"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "vlan-filtering": {"default": False},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "bridge", "port"): {
        "shape": "collection",
        "primary_keys": ("bridge", "interface"),
        "fields": {
            "bridge": {},
            "interface": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "bridge", "vlan"): {
        "shape": "collection",
        "primary_keys": ("bridge", "vlan-ids"),
        "fields": {
            "bridge": {},
            "vlan-ids": {},
            "tagged": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "wireguard"): {
        "shape": "collection",
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "listen-port": {},
            "mtu": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("interface", "wireguard", "peers"): {
        "shape": "collection",
        # public-key is public (not a secret); private keys live on the interface
        # and the read-only user can't read them anyway.
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "interface": {},
            "public-key": {},
            "allowed-address": {},
            "comment": {"can_disable": True, "remove_value": ""},
        },
    },
    ("ip", "dns", "static"): {
        "shape": "collection",
        # Keyed by name only: our managed records have unique names, and RouterOS
        # may omit the default 'type' (A) from API output, which would break a
        # composite (name,type) key. 'type' is a managed field with default A.
        "primary_keys": ("name",),
        "fields": {
            "name": {},
            "type": {"default": "A"},
            "address": {},
            "comment": {"can_disable": True, "remove_value": ""},
            "disabled": {"default": False},
        },
    },
    ("ip", "firewall", "address-list"): {
        "shape": "collection",
        # Address-lists are sets: order-independent, natural key (list, address).
        # Reuses the generic collection backend. Dynamic entries (from scripts /
        # firewall) are filtered out automatically; runtime fields like
        # creation-time/timeout are simply not in desired, so they're ignored.
        "primary_keys": ("list", "address"),
        "fields": {
            "list": {},
            "address": {},
            "comment": {"can_disable": True, "remove_value": ""},
            "disabled": {"default": False},
        },
    },
    ("ip", "firewall", "filter"): {
        # Ordered path: no natural key. Rules are matched by an embedded
        # comment tag [salt:<name>]; untagged rules are invisible to the engine
        # (never matched, updated, or purged). The engine manages rule *content*
        # only; rule order is left as-is (adopted rules keep their position, new
        # rules append). `stratify` groups rows by chain for adopt tag naming.
        "shape": "ordered",
        "key": "comment_tag",
        "tag_prefix": "salt:",
        "stratify": ("chain",),
        "fields": _fw_fields(),
    },
    ("ip", "firewall", "nat"): {
        "shape": "ordered",
        "key": "comment_tag",
        "tag_prefix": "salt:",
        "stratify": ("chain",),
        "fields": _fw_fields({"to-addresses": {}, "to-ports": {}}),
    },
    ("ip", "firewall", "raw"): {
        "shape": "ordered",
        "key": "comment_tag",
        "tag_prefix": "salt:",
        "stratify": ("chain",),
        "fields": _fw_fields(),
    },
    ("system", "identity"): {
        "shape": "singleton",
        "fields": {
            "name": {"default": "MikroTik"},
        },
    },
    ("system", "clock"): {
        "shape": "singleton",
        # Only fields present in desired pillar are diffed; unlisted fields use a
        # plain normalized compare, so an exhaustive field map isn't required.
        "fields": {},
    },
    ("system", "ntp", "client"): {
        "shape": "singleton",
        "fields": {},
    },
    ("snmp",): {
        "shape": "singleton",
        "fields": {},
    },
}


def __virtual__():
    if "proxy" not in __opts__:
        return False, "mikrotik execution module is only available on proxy minions"
    if __opts__["proxy"].get("proxytype") != "mikrotik":
        return False, "proxytype is not mikrotik"
    return __virtualname__


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------
def path(*parts):
    """
    Read a RouterOS menu path and return it as a list of dicts.

    CLI example:

        salt-sproxy <device> mikrotik.path system resource
    """
    return __proxy__["mikrotik.path"](*parts)


def facts():
    """
    Return the device inventory facts (same data exposed as the ``mikrotik`` grain).

    CLI example:

        salt-sproxy <device> mikrotik.facts
    """
    return __proxy__["mikrotik.grains"]().get("mikrotik", {})


# ---------------------------------------------------------------------------
# Internal: normalization, keys, diffing
# ---------------------------------------------------------------------------
def _norm(value):
    """
    Canonicalize a value for comparison only (never for writing). RouterOS and
    librouteros are inconsistent about bool spelling (True/'true'/'yes'); fold
    them all to one form so desired (from YAML) and live (from the API) compare
    equal when they mean the same thing.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    text = str(value)
    low = text.lower()
    if low in ("yes", "true"):
        return "true"
    if low in ("no", "false"):
        return "false"
    return text


def _schema(parts):
    key = tuple(parts)
    if key not in _SCHEMA:
        raise KeyError("No mikrotik schema for path /{}".format("/".join(key)))
    return key, _SCHEMA[key]


def _is_dynamic_or_builtin(row):
    return _norm(row.get("dynamic")) == "true" or _norm(row.get("builtin")) == "true"


def _matches_restrict(row, restrict):
    """
    restrict is a dict of field -> value (or list of values). A row matches when
    every restrict field equals (one of) the given value(s).
    """
    for field, wanted in restrict.items():
        allowed = wanted if isinstance(wanted, (list, tuple)) else [wanted]
        if _norm(row.get(field)) not in {_norm(a) for a in allowed}:
            return False
    return True


def _key(entry, primary_keys):
    missing = [pk for pk in primary_keys if pk not in entry]
    if missing:
        raise ValueError(
            "entry missing primary key field(s) {}: {!r}".format(missing, entry)
        )
    return tuple(_norm(entry[pk]) for pk in primary_keys)


def _field_diff(desired, live, fields):
    """
    Return {field: {"old": ..., "new": ...}} for fields present in *desired*
    that differ from *live*. Only desired fields are considered (additive: we
    never reset device fields the pillar doesn't mention). Computed fields are
    skipped, and a desired value equal to a field default that the device
    omitted is not a diff.
    """
    diff = {}
    for field, want in desired.items():
        meta = fields.get(field, {})
        if meta.get("computed"):
            continue
        have = live.get(field)
        if field not in live and "default" in meta and _norm(want) == _norm(meta["default"]):
            continue
        if _norm(have) != _norm(want):
            diff[field] = {"old": have, "new": want}
    return diff


def _clean_for_write(entry, fields):
    """Drop computed fields from a desired entry before writing it."""
    return {
        f: v
        for f, v in entry.items()
        if not fields.get(f, {}).get("computed")
    }


# ---------------------------------------------------------------------------
# Comment-tag helpers (for the "ordered" shape: firewall filter/nat/raw).
# Identity is an embedded tag [salt:<name>] inside the rule comment. The rest
# of the comment is free human text. Only tagged rows are managed.
# ---------------------------------------------------------------------------
def _tag_re(prefix):
    return r"\[" + re.escape(prefix) + r"([^\]]+)\]"


def _extract_tag(comment, prefix="salt:"):
    """
    Return the ``<name>`` from a ``[salt:<name>]`` token embedded anywhere in
    ``comment`` (surrounding free text/whitespace is tolerated), or None.
    """
    if not comment:
        return None
    match = re.search(_tag_re(prefix), str(comment))
    return match.group(1).strip() if match else None


def _strip_tag(comment, prefix="salt:"):
    """Return ``comment`` with any ``[salt:<name>]`` token (and surrounding
    whitespace) removed -- i.e. just the free human text."""
    if not comment:
        return ""
    return re.sub(r"\s*" + _tag_re(prefix), "", str(comment)).strip()


def _render_comment(text, tag, prefix="salt:"):
    """Compose the comment written to the device: free text + ``[salt:<tag>]``.
    Any pre-existing tag in ``text`` is stripped first to avoid duplication."""
    token = "[{}{}]".format(prefix, tag)
    free = _strip_tag(text, prefix)
    return "{} {}".format(free, token) if free else token


def _desired_tag(entry, prefix="salt:"):
    """The tag for a desired entry: an explicit ``tag:`` field, else a tag
    embedded in its ``comment``. Returns None if neither is present."""
    tag = entry.get("tag")
    if tag:
        return str(tag)
    return _extract_tag(entry.get("comment"), prefix)


# ---------------------------------------------------------------------------
# Reconciliation backends
# ---------------------------------------------------------------------------
def _writable(row, fields):
    """Subset of a row limited to writable (non-computed) schema fields."""
    return {f: row[f] for f in fields if f in row and not fields[f].get("computed")}


def _plan_collection(parts, schema, desired, purge, restrict):
    """Compute the changes dict for a collection path without applying anything."""
    pks = schema["primary_keys"]
    fields = schema["fields"]

    for d in desired:
        if "place_before" in d or "place_after" in d:
            raise ValueError(
                "placement (place_before/place_after) is only supported on "
                "ordered firewall paths, not /{}".format("/".join(parts))
            )

    live = [r for r in __proxy__["mikrotik.path"](*parts) if not _is_dynamic_or_builtin(r)]
    if restrict:
        live = [r for r in live if _matches_restrict(r, restrict)]
        desired = [d for d in desired if _matches_restrict(d, restrict)]

    live_by_key = {_key(r, pks): r for r in live}
    changes = {"added": [], "updated": [], "removed": []}
    matched = set()

    for entry in desired:
        key = _key(entry, pks)
        cur = live_by_key.get(key)
        keystr = ",".join(key)
        pk = {p: entry[p] for p in pks}
        if cur is None:
            changes["added"].append(
                {"key": keystr, "pk": pk, "entry": _clean_for_write(entry, fields)}
            )
        else:
            matched.add(key)
            diff = _field_diff(entry, cur, fields)
            if diff:
                changes["updated"].append(
                    {"key": keystr, "pk": pk, "id": cur[".id"], "diff": diff}
                )

    if purge:
        for key, row in live_by_key.items():
            if key not in matched:
                changes["removed"].append(
                    {
                        "key": ",".join(key),
                        "pk": {p: row.get(p) for p in pks},
                        "id": row[".id"],
                        "entry": _writable(row, fields),
                    }
                )

    return changes


def _plan_ordered(parts, schema, desired, purge=False, restrict=None):
    """
    Compute the changes dict for an ordered (comment-tag keyed) path.

    Only tagged live rows are considered; untagged rows are ignored entirely
    (never matched, updated, or purged). Each desired entry must carry a tag
    (explicit ``tag:`` field or ``[salt:..]`` in its ``comment``). The engine
    renders ``comment`` as ``<free text> [salt:<tag>]`` for both writing and
    comparison, so the tag is never a false diff.

    Rule *content* is managed (add/update/remove). A NEW rule may set
    ``place_before: <tag>`` to be inserted immediately before an existing
    managed rule (resolved to its live ``.id`` and passed to RouterOS ``add``);
    this is honored only on insert -- an existing rule is never moved. Reordering
    an existing rule is intentionally out of scope: RouterOS ``move`` can't be
    undone by the commit-confirm rollback, whereas an insert inverts cleanly to a
    remove. Rules adopted from the device keep their existing order; a new rule
    with no ``place_before`` is appended.
    """
    fields = schema["fields"]
    prefix = schema.get("tag_prefix", "salt:")

    live = [r for r in __proxy__["mikrotik.path"](*parts) if not _is_dynamic_or_builtin(r)]
    if restrict:
        live = [r for r in live if _matches_restrict(r, restrict)]
        desired = [d for d in desired if _matches_restrict(d, restrict)]

    live_tagged = []  # [(tag, row)] in device order
    live_by_tag = {}
    for row in live:
        tag = _extract_tag(row.get("comment"), prefix)
        if tag is None:
            continue  # untagged -> invisible
        live_tagged.append((tag, row))
        live_by_tag[tag] = row

    changes = {"added": [], "updated": [], "removed": []}
    matched = set()

    for entry in desired:
        tag = _desired_tag(entry, prefix)
        if not tag:
            raise ValueError(
                "ordered entry needs a tag (set 'tag:' or embed [salt:..] in "
                "'comment'): {!r}".format(entry)
            )
        if entry.get("place_after"):
            raise ValueError(
                "place_after is not supported; anchor the following rule with "
                "place_before instead (entry tag {!r})".format(tag)
            )
        place_before = entry.get("place_before")
        write_entry = {k: v for k, v in entry.items() if k not in _RESERVED}
        write_entry["comment"] = _render_comment(entry.get("comment"), tag, prefix)
        write_entry = _clean_for_write(write_entry, fields)
        cur = live_by_tag.get(tag)
        if cur is None:
            add_item = {"key": tag, "tag": tag, "entry": write_entry}
            if place_before:
                anchor = live_by_tag.get(str(place_before))
                if anchor is None:
                    raise ValueError(
                        "place_before anchor [{0}{1}] for new rule [{0}{2}] is not "
                        "a live managed rule on /{3}; placement anchors must be "
                        "existing tagged rules (adopt the target first if it is "
                        "untagged)".format(prefix, place_before, tag, "/".join(parts))
                    )
                add_item["place_before"] = str(place_before)
                add_item["place_before_id"] = anchor[".id"]
            changes["added"].append(add_item)
        else:
            matched.add(tag)
            diff = _field_diff(write_entry, cur, fields)
            if diff:
                changes["updated"].append(
                    {"key": tag, "tag": tag, "id": cur[".id"], "diff": diff}
                )

    if purge:
        for tag, row in live_tagged:
            if tag not in matched:
                changes["removed"].append(
                    {
                        "key": tag,
                        "tag": tag,
                        "id": row[".id"],
                        "entry": _writable(row, fields),
                    }
                )

    return changes


def _apply_ordered(parts, changes):
    """Apply an ordered changes dict: updates -> adds -> removes (same order as
    collections, so existing connectivity survives until the reconcile ends)."""
    for upd in changes["updated"]:
        data = {".id": upd["id"]}
        data.update({f: dd["new"] for f, dd in upd["diff"].items()})
        __proxy__["mikrotik.update"](parts, data)
    for add in changes["added"]:
        data = dict(add["entry"])
        if add.get("place_before_id"):
            # Insert immediately before the anchor row. RouterOS `add` accepts
            # `place-before=<.id>`; absent it, the row appends. The inverse of an
            # add is a position-independent remove, so this stays rollback-safe.
            data["place-before"] = add["place_before_id"]
        __proxy__["mikrotik.add"](parts, data)
    if changes["removed"]:
        __proxy__["mikrotik.remove"](parts, [r["id"] for r in changes["removed"]])


def _has_changes(changes):
    return bool(changes["added"] or changes["updated"] or changes["removed"])


def manage_collection(path, desired, purge=False, restrict=None, test=False):
    """
    Reconcile a keyed collection path against ``desired`` (a list of dicts).

    Matching is by the path's ``primary_keys``. Dynamic/builtin rows are never
    touched. ``purge=True`` removes live rows that aren't in ``desired`` (opt-in;
    use ``restrict`` to scope which rows are eligible for purge). Returns a
    changes dict ``{"added": [...], "updated": [...], "removed": [...]}``.

    CLI example (dry-run):

        salt-sproxy <device> mikrotik.manage_collection \\
            path='[ip, address]' desired='[{...}]' test=True
    """
    parts, schema = _schema(path)
    if schema["shape"] != "collection":
        raise ValueError("/{} is not a collection".format("/".join(parts)))
    changes = _plan_collection(parts, schema, desired, purge, restrict)
    if not test:
        _apply_collection(parts, changes)
    return changes


def manage_ordered(path, desired, purge=False, restrict=None, test=False):
    """
    Reconcile an ordered (comment-tag keyed) path -- /ip/firewall/{filter,nat,raw}.

    Only rows tagged ``[salt:<name>]`` are managed; untagged rows are never
    touched. ``purge=True`` removes managed-but-absent rows (never untagged
    ones). Rule content is managed; rule order is left as-is. Returns
    ``{"added","updated","removed"}``.

    CLI example (dry-run):

        salt-sproxy <device> mikrotik.manage_ordered \\
            path='[ip, firewall, nat]' desired='[{...}]' test=True
    """
    parts, schema = _schema(path)
    if schema["shape"] != "ordered":
        raise ValueError("/{} is not an ordered path".format("/".join(parts)))
    changes = _plan_ordered(parts, schema, desired, purge, restrict)
    if not test:
        _apply_ordered(parts, changes)
    return changes


def manage(path, desired, purge=False, restrict=None, test=False):
    """
    Shape-dispatching reconcile entry point used by the ``mikrotik.collection``
    state. Routes collection paths to the keyed backend and firewall
    filter/nat/raw to the ordered (comment-tag) backend.
    """
    parts, schema = _schema(path)
    shape = schema["shape"]
    if shape == "collection":
        changes = _plan_collection(parts, schema, desired, purge, restrict)
        if not test:
            _apply_collection(parts, changes)
        return changes
    if shape == "ordered":
        changes = _plan_ordered(parts, schema, desired, purge, restrict)
        if not test:
            _apply_ordered(parts, changes)
        return changes
    raise ValueError("/{} is not a manageable collection path".format("/".join(parts)))


def adopt(path, restrict=None, dry_run=True, tag_prefix="salt:"):
    """
    One-time bootstrap for an ordered firewall path: write ``[salt:<tag>]`` tags
    onto existing untagged rules so they become manageable, and emit the
    matching pillar entries.

    For each live (non-dynamic) row without a salt tag, a stable tag
    ``<chain>-<NNN>`` (positional, deduped against existing tags) is generated
    and the row's comment becomes ``<existing comment> [salt:<tag>]``. With
    ``dry_run=False`` the tag is written to the device. Either way the would-be
    pillar entries are returned (in device order, ready to paste under
    ``mikrotik:firewall:<path>:rules``) so that a subsequent ``test=True`` run is
    zero-diff.

    CLI examples:

        salt-sproxy <device> mikrotik.adopt '[ip, firewall, nat]' dry_run=True
        salt-sproxy <device> mikrotik.adopt '[ip, firewall, filter]' \\
            restrict='{chain: input}' dry_run=False
    """
    parts, schema = _schema(path)
    if schema["shape"] != "ordered":
        raise ValueError("/{} is not an ordered path".format("/".join(parts)))
    fields = schema["fields"]
    prefix = schema.get("tag_prefix", tag_prefix)
    stratify = schema.get("stratify", ())

    live = [r for r in __proxy__["mikrotik.path"](*parts) if not _is_dynamic_or_builtin(r)]
    if restrict:
        live = [r for r in live if _matches_restrict(r, restrict)]

    used = {
        _extract_tag(r.get("comment"), prefix)
        for r in live
        if _extract_tag(r.get("comment"), prefix)
    }
    counters = {}
    result = {"path": list(parts), "tagged": [], "already_tagged": [], "rules": []}

    for row in live:
        tag = _extract_tag(row.get("comment"), prefix)
        if tag:
            result["already_tagged"].append(tag)
        else:
            base = "-".join(_norm(row.get(f)) for f in stratify) if stratify else parts[-1]
            base = base or parts[-1]
            while True:
                counters[base] = counters.get(base, 0) + 1
                tag = "{}-{:03d}".format(base, counters[base])
                if tag not in used:
                    break
            used.add(tag)
            new_comment = _render_comment(row.get("comment"), tag, prefix)
            result["tagged"].append(
                {"tag": tag, "id": row[".id"], "comment": new_comment}
            )
            if not dry_run:
                __proxy__["mikrotik.update"](parts, {".id": row[".id"], "comment": new_comment})

        # Emit a clean pillar entry: tag + writable fields. The free-text comment
        # has its tag stripped; default-valued and empty/unset fields are dropped
        # (the additive engine ignores absent fields, so this stays zero-diff)
        # -- e.g. RouterOS returns log-prefix="" on every rule, which we omit.
        entry = {"tag": tag}
        for field, value in _writable(row, fields).items():
            if field == "comment":
                free = _strip_tag(value, prefix)
                if free:
                    entry["comment"] = free
                continue
            meta = fields.get(field, {})
            if "default" in meta and _norm(value) == _norm(meta["default"]):
                continue
            if _norm(value) == "":  # unset/empty field -> omit
                continue
            entry[field] = value
        result["rules"].append(entry)

    return result


def manage_singleton(path, settings, test=False):
    """
    Reconcile a single-value path (e.g. /system/identity) against ``settings``
    (a dict of field=value). Returns ``{}`` when already in sync, otherwise
    ``{"diff": {...}}``.

    CLI example (dry-run):

        salt-sproxy <device> mikrotik.manage_singleton \\
            path='[system, identity]' settings='{name: <device>}' test=True
    """
    parts, schema = _schema(path)
    if schema["shape"] != "singleton":
        raise ValueError("/{} is not a singleton".format("/".join(parts)))
    fields = schema["fields"]

    live = __proxy__["mikrotik.path"](*parts)
    cur = live[0] if live else {}
    diff = _field_diff(settings, cur, fields)
    if not diff:
        return {}

    if not test:
        data = {f: dd["new"] for f, dd in diff.items()}
        __proxy__["mikrotik.update"](parts, data)

    return {"diff": diff}


def _public(row):
    """Strip RouterOS-internal/derived keys from a row for human-readable output."""
    return {k: v for k, v in row.items() if not k.startswith(".")}


def _apply_collection(parts, changes):
    """
    Apply a computed changes dict. Order: updates, then adds, then removes --
    so existing connectivity survives until the end of the reconcile (relevant
    when purge is enabled on the device that carries our own management path).
    """
    for upd in changes["updated"]:
        data = {".id": upd["id"]}
        data.update({f: dd["new"] for f, dd in upd["diff"].items()})
        __proxy__["mikrotik.update"](parts, data)
    for add in changes["added"]:
        __proxy__["mikrotik.add"](parts, add["entry"])
    if changes["removed"]:
        __proxy__["mikrotik.remove"](parts, [r["id"] for r in changes["removed"]])


# ---------------------------------------------------------------------------
# Commit-confirm rollback (inverse-diff dead-man's switch)
# ---------------------------------------------------------------------------
def _ros_quote(value):
    """Quote a value for a RouterOS console script string."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$")
    return '"' + text + '"'


def _find_clause(pk):
    return " ".join("{}={}".format(k, _ros_quote(v)) for k, v in pk.items())


def _tag_find_clause(tag, prefix="salt:"):
    """A RouterOS ``[find ...]`` clause that locates a row by its embedded
    ``[salt:<tag>]`` comment token. ``comment~"..."`` is a regex match, so the
    literal brackets are escaped (``\\[`` / ``\\]``); ``_ros_quote`` then escapes
    those backslashes for the console string layer."""
    pattern = "\\[" + prefix + tag + "\\]"
    return "comment~{}".format(_ros_quote(pattern))


def _find_for(schema, item):
    """Build the ``[find ...]`` selector for a change item, by schema shape:
    primary-key clause for collections, comment-tag clause for ordered paths."""
    if schema.get("key") == "comment_tag":
        return _tag_find_clause(item["tag"], schema.get("tag_prefix", "salt:"))
    return _find_clause(item["pk"])


def _build_inverse_script(parts, schema, changes, marker_name):
    """
    Build a RouterOS console script that undoes ``changes`` (restores the prior
    state), then removes its own scheduler so it runs exactly once.

    Rows are located by primary key (collections) or by ``[salt:<tag>]`` comment
    (ordered firewall paths). Content changes (add/update/remove) are reverted;
    rule order is never changed by the engine, so there is nothing to revert.
    """
    cmd = "/" + "/".join(parts)
    lines = []
    # We ADDED rows -> rollback REMOVES them.
    for add in changes["added"]:
        lines.append("{} remove [find {}]".format(cmd, _find_for(schema, add)))
    # We UPDATED fields -> rollback restores the OLD values.
    for upd in changes["updated"]:
        sets = [
            "{}={}".format(field, _ros_quote(dd["old"]))
            for field, dd in upd["diff"].items()
            if dd["old"] is not None  # v1: can't restore a field that was absent
        ]
        if sets:
            lines.append(
                "{} set [find {}] {}".format(cmd, _find_for(schema, upd), " ".join(sets))
            )
    # We REMOVED rows -> rollback RE-ADDS them (full content incl. tagged comment).
    for rem in changes["removed"]:
        kv = " ".join("{}={}".format(k, _ros_quote(v)) for k, v in rem["entry"].items())
        lines.append("{} add {}".format(cmd, kv))
    # Self-removal: this scheduler fires once, then deletes itself.
    lines.append("/system/scheduler remove [find name={}]".format(_ros_quote(marker_name)))
    return "\n".join(lines)


def _disarm(marker_name):
    menu = ["system", "scheduler"]
    ids = [r[".id"] for r in __proxy__["mikrotik.path"](*menu) if r.get("name") == marker_name]
    if ids:
        __proxy__["mikrotik.remove"](menu, ids)


def commit_confirm(path, desired, purge=False, restrict=None, timeout_minutes=3,
                   _skip_confirm=False):
    """
    Apply a collection or ordered (firewall) change with a router-side
    auto-revert safety net.

    Plans the change, arms a ``/system/scheduler`` that will undo it (inverse
    diff) after ``timeout_minutes`` and then self-delete, applies the change,
    then verifies reachability over a FRESH API connection. If reachable, the
    scheduler is cancelled (commit confirmed); if not, it is left to fire and
    auto-revert. ``_skip_confirm=True`` deliberately leaves the rollback armed
    (for testing the auto-revert path on a safe path).

    CLI example:

        salt-sproxy <device> mikrotik.commit_confirm \\
            path='[ip, firewall, address-list]' desired='[{...}]' timeout_minutes=3
    """
    parts, schema = _schema(path)
    shape = schema["shape"]
    if shape == "collection":
        changes = _plan_collection(parts, schema, desired, purge, restrict)
        apply_fn = lambda: _apply_collection(parts, changes)  # noqa: E731
    elif shape == "ordered":
        changes = _plan_ordered(parts, schema, desired, purge, restrict)
        apply_fn = lambda: _apply_ordered(parts, changes)  # noqa: E731
    else:
        raise ValueError("/{} is not a commit-confirmable path".format("/".join(parts)))

    if not _has_changes(changes):
        return {"changes": changes, "armed": False, "confirmed": True,
                "comment": "no changes; nothing to apply"}

    import binascii
    import os

    marker = "salt-rollback-" + binascii.hexlify(os.urandom(4)).decode()
    script = _build_inverse_script(parts, schema, changes, marker)

    # Arm the dead-man's switch BEFORE applying, so a mid-apply lockout is covered.
    __proxy__["mikrotik.add"](
        ["system", "scheduler"],
        {
            "name": marker,
            "interval": "{}m".format(timeout_minutes),
            "on-event": script,
            "policy": "read,write,test",
            "comment": "salt commit-confirm auto-revert; delete on confirm",
        },
    )

    apply_fn()

    if _skip_confirm:
        return {"changes": changes, "armed": True, "confirmed": False, "rollback": marker,
                "comment": "confirm skipped; auto-revert in {}m".format(timeout_minutes)}

    if __proxy__["mikrotik.fresh_ping"]():
        _disarm(marker)
        return {"changes": changes, "armed": True, "confirmed": True,
                "comment": "applied and confirmed reachable; rollback cancelled"}

    return {"changes": changes, "armed": True, "confirmed": False, "rollback": marker,
            "comment": "NOT reachable after apply; auto-revert in {}m".format(timeout_minutes)}
