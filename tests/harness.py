# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
"""
Offline test harness for the mikrotik formula.

The engine (``_modules/mikrotik.py``) is pure Python whose only seam is the
``__proxy__`` dunder it calls for device I/O (``mikrotik.path/add/update/
remove/fresh_ping``). This harness:

  * loads the engine/state module straight from its file (no Salt loader), and
  * provides ``FakeDevice``, an in-memory RouterOS stand-in that faithfully
    models ``place-before`` insertion order, so reconcile + apply can be tested
    end-to-end with no Salt install and no real router.

No third-party deps: run with ``python3 -m unittest discover -s tests -v``.
"""

import importlib.util
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_module(relpath, name):
    """Import a formula module file by path, bypassing Salt's loader."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_engine():
    return load_module("_modules/mikrotik.py", "mikrotik_engine")


def load_state():
    return load_module("_states/mikrotik.py", "mikrotik_state")


_TAG_RE = re.compile(r"\[salt:([^\]]+)\]")


class FakeDevice:
    """
    In-memory RouterOS API stand-in.

    Tables are ordered lists of row dicts keyed by the menu path tuple. ``.id``
    values are assigned on insert (``*1``, ``*2``, ...). ``add`` honors a
    ``place-before=<.id>`` directive exactly like RouterOS: the new row is
    inserted immediately before the referenced row, else appended. This is what
    makes ordering assertions meaningful.
    """

    def __init__(self):
        self.tables = {}
        self._counter = 0

    def _next_id(self):
        self._counter += 1
        return "*{}".format(self._counter)

    def seed(self, parts, rows):
        out = []
        for r in rows:
            r = dict(r)
            r.setdefault(".id", self._next_id())
            out.append(r)
        self.tables[tuple(parts)] = out
        return self

    # --- proxy surface (signatures match how the engine calls __proxy__) ---
    def path(self, *parts):
        return [dict(r) for r in self.tables.get(tuple(parts), [])]

    def add(self, parts, data):
        rows = self.tables.setdefault(tuple(parts), [])
        data = dict(data)
        place_before = data.pop("place-before", None)
        row = dict(data)
        row[".id"] = self._next_id()
        if place_before is not None:
            idx = next(
                (i for i, r in enumerate(rows) if r.get(".id") == place_before),
                len(rows),
            )
            rows.insert(idx, row)
        else:
            rows.append(row)
        return row[".id"]

    def update(self, parts, data):
        data = dict(data)
        rid = data.pop(".id", None)
        rows = self.tables.setdefault(tuple(parts), [])
        if rid is None:  # singleton: the sole record
            if rows:
                rows[0].update(data)
            else:
                rows.append(dict(data))
            return True
        for r in rows:
            if r.get(".id") == rid:
                r.update(data)
                break
        return True

    def remove(self, parts, ids):
        idset = set(ids)
        key = tuple(parts)
        self.tables[key] = [r for r in self.tables.get(key, []) if r.get(".id") not in idset]
        return True

    def fresh_ping(self):
        return True

    # --- wiring + assertions helpers ---
    def proxy(self):
        return {
            "mikrotik.path": self.path,
            "mikrotik.add": self.add,
            "mikrotik.update": self.update,
            "mikrotik.remove": self.remove,
            "mikrotik.fresh_ping": self.fresh_ping,
        }

    def tags(self, parts):
        """Ordered list of [salt:<tag>] tags currently on a path (device order)."""
        out = []
        for r in self.tables.get(tuple(parts), []):
            m = _TAG_RE.search(str(r.get("comment", "")))
            if m:
                out.append(m.group(1))
        return out

    def comments(self, parts):
        return [r.get("comment") for r in self.tables.get(tuple(parts), [])]
