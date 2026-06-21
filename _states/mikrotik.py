# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Reconciliation design derived from the community.routeros Ansible collection:
#   Copyright (c) Ansible Project -- GPL-3.0-or-later
#   https://github.com/ansible-collections/community.routeros
"""
State module for declarative MikroTik RouterOS config management.

States call the schema-driven engine in the ``mikrotik`` execution module and
return the standard Salt ``{name, result, changes, comment}`` shape. Under
``test=True`` they compute and report the planned changes without touching the
device (``result`` is ``None`` when changes are pending).

Example SLS::

    manage_ip_addresses:
      mikrotik.collection:
        - path: [ip, address]
        - entries:
            - {address: 192.0.2.1/24, interface: vlan2, comment: "lan"}
        - purge: false

    set_identity:
      mikrotik.singleton:
        - path: [system, identity]
        - settings: {name: <device>}
"""

__virtualname__ = "mikrotik"


def __virtual__():
    if "proxy" not in __opts__:
        return False, "mikrotik state module is only available on proxy minions"
    if __opts__["proxy"].get("proxytype") != "mikrotik":
        return False, "proxytype is not mikrotik"
    return __virtualname__


def _collection_changes(name_to_change):
    """Flatten the engine changes dict into a Salt ret['changes'] mapping."""
    changes = {}
    for add in name_to_change["added"]:
        changes["add {}".format(add["key"])] = {"old": None, "new": add["entry"]}
    for upd in name_to_change["updated"]:
        changes[upd["key"]] = {f: dd for f, dd in upd["diff"].items()}
    for rem in name_to_change["removed"]:
        changes["remove {}".format(rem["key"])] = {"old": rem["entry"], "new": None}
    return changes


def collection(name, path, entries, purge=False, restrict=None, confirm_timeout=None):
    """
    Ensure a keyed RouterOS collection path matches ``entries``.

    path
        RouterOS menu path as a list, e.g. ``[ip, address]``.
    entries
        List of desired rows (dicts). Each must include the path's primary-key
        fields.
    purge
        When True, remove live rows not present in ``entries`` (dynamic/builtin
        rows are always protected). Default False (additive).
    restrict
        Optional dict scoping both matching and purge to a subset of rows, e.g.
        ``{chain: input}``.
    confirm_timeout
        When set (minutes), apply via the commit-confirm rollback: a router-side
        inverse-diff auto-revert is armed before applying and cancelled only if
        reachability is reconfirmed afterwards. Use on lockout-risky paths
        (firewall). Ignored in test mode. Default None (apply directly).

    For ordered firewall paths (filter/nat/raw) the engine manages rule content;
    a new rule may carry ``place_before: <tag>`` to be inserted before an
    existing managed rule (honored on insert only -- an existing rule is never
    moved). Reordering an existing rule is out of scope -- RouterOS ``move``
    can't be undone by the rollback; an insert inverts cleanly to a remove.
    """
    ret = {"name": name, "result": True, "changes": {}, "comment": ""}
    test = __opts__["test"]

    # Dry-run always just plans; never arms a rollback or touches the device.
    if test:
        try:
            engine_changes = __salt__["mikrotik.manage"](
                path, entries, purge=purge, restrict=restrict, test=True
            )
        except Exception as exc:  # pylint: disable=broad-except
            ret["result"] = False
            ret["comment"] = "mikrotik.collection failed: {}".format(exc)
            return ret
        changes = _collection_changes(engine_changes)
        if not changes:
            ret["comment"] = "/{} already in the desired state".format("/".join(path))
            return ret
        ret["result"] = None
        ret["changes"] = changes
        ret["comment"] = "/{}: {} change(s) would be applied".format(
            "/".join(path), len(changes)
        )
        return ret

    # Apply -- optionally guarded by the commit-confirm rollback.
    cc = None
    try:
        if confirm_timeout:
            cc = __salt__["mikrotik.commit_confirm"](
                path, entries, purge=purge, restrict=restrict,
                timeout_minutes=confirm_timeout,
            )
            engine_changes = cc["changes"]
        else:
            engine_changes = __salt__["mikrotik.manage"](
                path, entries, purge=purge, restrict=restrict, test=False
            )
    except Exception as exc:  # pylint: disable=broad-except
        ret["result"] = False
        ret["comment"] = "mikrotik.collection failed: {}".format(exc)
        return ret

    changes = _collection_changes(engine_changes)
    if not changes:
        ret["comment"] = "/{} already in the desired state".format("/".join(path))
        return ret
    ret["changes"] = changes

    if cc is not None and not cc.get("confirmed", True):
        # Armed but reachability not reconfirmed: the device will auto-revert.
        ret["result"] = False
        ret["comment"] = (
            "/{}: applied but NOT reconfirmed reachable; auto-revert pending "
            "({})".format("/".join(path), cc.get("rollback"))
        )
    elif confirm_timeout:
        ret["comment"] = (
            "/{}: {} change(s) applied and confirmed; rollback ({}m) cancelled".format(
                "/".join(path), len(changes), confirm_timeout
            )
        )
    else:
        ret["comment"] = "/{}: {} change(s) applied".format("/".join(path), len(changes))
    return ret


def singleton(name, path, settings):
    """
    Ensure a single-value RouterOS path (e.g. /system/identity) matches
    ``settings`` (a dict of field=value).
    """
    ret = {"name": name, "result": True, "changes": {}, "comment": ""}
    test = __opts__["test"]

    try:
        engine_changes = __salt__["mikrotik.manage_singleton"](path, settings, test=test)
    except Exception as exc:  # pylint: disable=broad-except
        ret["result"] = False
        ret["comment"] = "mikrotik.singleton failed: {}".format(exc)
        return ret

    if not engine_changes:
        ret["comment"] = "/{} already in the desired state".format("/".join(path))
        return ret

    ret["changes"] = engine_changes["diff"]
    if test:
        ret["result"] = None
        ret["comment"] = "/{} would be updated".format("/".join(path))
    else:
        ret["comment"] = "/{} updated".format("/".join(path))
    return ret
