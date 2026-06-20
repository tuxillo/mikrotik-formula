# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Manage /ip/address on a MikroTik proxy minion from pillar data under
# `mikrotik:ip_address`. Run dry-run first:
#   salt-sproxy <device> state.apply mikrotik.addresses test=True
{%- set cfg = salt['pillar.get']('mikrotik:ip_address', {}) %}
{%- if cfg.get('entries') %}
mikrotik_ip_address:
  mikrotik.collection:
    - path: [ip, address]
    - entries: {{ cfg['entries'] | json }}
    - purge: {{ cfg.get('purge', False) | json }}
{%- else %}
mikrotik_ip_address_noop:
  test.succeed_without_changes:
    - name: "no mikrotik:ip_address pillar data; nothing to manage"
{%- endif %}
