# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Manage /ip/dns/static from pillar under `mikrotik:dns_static`.
# Dry-run first:
#   salt-sproxy --sync-all <device> state.apply mikrotik.dns test=True
{%- set ds = salt['pillar.get']('mikrotik:dns_static', {}) %}
{%- if ds.get('entries') %}
mikrotik_dns_static:
  mikrotik.collection:
    - path: [ip, dns, static]
    - entries: {{ ds['entries'] | json }}
    - purge: {{ ds.get('purge', False) | json }}
{%- if ds.get('confirm_timeout') %}
    - confirm_timeout: {{ ds['confirm_timeout'] }}
{%- endif %}
{%- else %}
mikrotik_dns_static_noop:
  test.succeed_without_changes:
    - name: "no mikrotik:dns_static pillar data; nothing to manage"
{%- endif %}
