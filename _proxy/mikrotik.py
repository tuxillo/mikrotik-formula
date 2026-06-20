# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
"""
Salt proxy module for MikroTik RouterOS devices via the binary API.

Opens a librouteros API connection using the proxy pillar block and exposes
read (``path``) and write (``add``/``update``/``remove``) primitives plus
device-fact grains. Connection details come from the proxy minion pillar::

    proxy:
      proxytype: mikrotik
      host: 192.0.2.1
      username: salt
      password: secret
      port: 8728
"""
import logging

try:
    from librouteros import connect
    from librouteros.exceptions import LibRouterosError

    HAS_LIBROUTEROS = True
except ImportError:
    HAS_LIBROUTEROS = False

log = logging.getLogger(__name__)

__proxyenabled__ = ["mikrotik"]
__virtualname__ = "mikrotik"

# Per-process connection state for this proxy minion.
DETAILS = {}


def __virtual__():
    if not HAS_LIBROUTEROS:
        return False, "The mikrotik proxy requires the 'librouteros' Python library"
    return __virtualname__


def _as_text(value):
    """
    Coerce a pillar value to str. The nacl renderer returns decrypted secrets as
    bytes; librouteros expects str credentials and rejects bytes, so decode here.
    """
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8")
    return value


def init(opts):
    """
    Open the RouterOS API connection from the proxy pillar block.
    """
    conf = opts.get("proxy", {})
    try:
        DETAILS["conf"] = {
            "host": conf["host"],
            "username": _as_text(conf["username"]),
            "password": _as_text(conf.get("password", "")),
            "port": conf.get("port", 8728),
        }
        DETAILS["api"] = connect(**DETAILS["conf"])
        DETAILS["host"] = conf["host"]
        DETAILS["initialized"] = True
    except (KeyError, LibRouterosError, OSError) as exc:
        log.error("mikrotik proxy: connection to %s failed: %s", conf.get("host"), exc)
        DETAILS["initialized"] = False
    return True


def initialized():
    return DETAILS.get("initialized", False)


def alive(opts):
    return ping()


def ping():
    api = DETAILS.get("api")
    if not api:
        return False
    try:
        tuple(api.path("system", "identity"))
        return True
    except LibRouterosError:
        return False


def shutdown(opts):
    api = DETAILS.get("api")
    if api:
        try:
            api.close()
        except LibRouterosError:
            pass
    DETAILS.clear()


def path(*parts):
    """
    Read a RouterOS menu path and return it as a list of dicts.
    """
    api = DETAILS.get("api")
    if not api:
        return []
    return [dict(row) for row in api.path(*parts)]


def add(parts, data):
    """
    Add a row under a RouterOS menu path. ``data`` is a dict of field=value.
    Returns the new RouterOS ``.id``.
    """
    res = DETAILS["api"].path(*parts)
    return res.add(**data)


def update(parts, data):
    """
    Update a record under a RouterOS menu path (issues ``set``). For collection
    rows ``data`` must include the ``.id``; for single-value paths (e.g.
    /system/identity) omit it. ``data`` is a dict of field=value.
    """
    res = DETAILS["api"].path(*parts)
    res.update(**data)
    return True


def remove(parts, ids):
    """
    Remove rows under a RouterOS menu path by their ``.id`` values.
    """
    res = DETAILS["api"].path(*parts)
    res.remove(*ids)
    return True


def fresh_ping():
    """
    Open a brand-new API connection and read /system/identity, then close it.

    Used by the commit-confirm rollback to detect a real lockout: a firewall
    change that blocks new connections often leaves the proxy's existing TCP
    session working (connection tracking), so only a fresh connection reveals
    that we've locked ourselves out. Returns True if a new login succeeds.
    """
    conf = DETAILS.get("conf")
    if not conf:
        return False
    api = None
    try:
        api = connect(**conf)
        tuple(api.path("system", "identity"))
        return True
    except (LibRouterosError, OSError):
        return False
    finally:
        if api is not None:
            try:
                api.close()
            except (LibRouterosError, OSError):
                pass


def _version_major(version):
    """
    Extract the RouterOS major version as an int from a version string such as
    "7.21.3 (stable)". Returns None if it can't be parsed.
    """
    if not version:
        return None
    try:
        return int(version.split(".", 1)[0])
    except (ValueError, AttributeError):
        return None


def grains():
    """
    Collect device facts as grains. Salt calls this after init() (so the API
    connection exists) and merges the result into the minion grains via
    proxy_merge_grains_in_module. Returned under the ``mikrotik`` grain key.
    """
    if not DETAILS.get("initialized"):
        return {}

    facts = {}
    resource = path("system", "resource")
    if resource:
        row = resource[0]
        version = row.get("version")
        facts.update(
            {
                "version": version,
                # RouterOS 6 and 7 differ in config syntax/paths, so the major
                # number is the main branching key for config-management states.
                "version_major": _version_major(version),
                "board_name": row.get("board-name"),
                "arch": row.get("architecture-name"),
                "cpu": row.get("cpu"),
            }
        )

    identity = path("system", "identity")
    if identity:
        facts["identity"] = identity[0].get("name")

    routerboard = path("system", "routerboard")
    if routerboard:
        row = routerboard[0]
        facts["model"] = row.get("model")
        facts["serial"] = row.get("serial-number")
        facts["firmware"] = row.get("current-firmware")

    # Interface names/types are stable enough to target on (e.g. presence of an
    # interface) without being mutable config state.
    facts["interfaces"] = [
        {"name": row.get("name"), "type": row.get("type")}
        for row in path("interface")
    ]

    return {"mikrotik": facts}
