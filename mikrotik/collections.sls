# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Generic driver for keyed RouterOS collections, from pillar under
# `mikrotik:collections`. Each entry is
#   <name>: {path: [..], entries: [..], purge: <bool>, confirm_timeout: <min>}
# Dry-run first:
#   salt-sproxy --sync-all <device> state.apply mikrotik.collections test=True
{%- set colls = salt['pillar.get']('mikrotik:collections', {}) %}
{%- if colls %}
{%- for cname, spec in colls.items() %}
mikrotik_collection_{{ cname }}:
  mikrotik.collection:
    - path: {{ spec['path'] | json }}
    - entries: {{ spec['entries'] | json }}
    - purge: {{ spec.get('purge', False) | json }}
{%- if spec.get('confirm_timeout') %}
    - confirm_timeout: {{ spec['confirm_timeout'] }}
{%- endif %}
{%- endfor %}
{%- else %}
mikrotik_collections_noop:
  test.succeed_without_changes:
    - name: "no mikrotik:collections pillar data; nothing to manage"
{%- endif %}
