# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Manage single-value RouterOS paths from pillar data under `mikrotik:singletons`.
# Each entry is {path: [..], settings: {field: value, ...}}. Run dry-run first:
#   salt-sproxy --sync-all <device> state.apply mikrotik.system test=True
{%- set singletons = salt['pillar.get']('mikrotik:singletons', {}) %}
{%- if singletons %}
{%- for name, spec in singletons.items() %}
mikrotik_singleton_{{ name }}:
  mikrotik.singleton:
    - path: {{ spec['path'] | json }}
    - settings: {{ spec['settings'] | json }}
{%- endfor %}
{%- else %}
mikrotik_singletons_noop:
  test.succeed_without_changes:
    - name: "no mikrotik:singletons pillar data; nothing to manage"
{%- endif %}
