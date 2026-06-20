# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Manage MikroTik firewall objects from pillar under `mikrotik:firewall`.
# Phase 2a: /ip/firewall/address-list (natural key, order-independent).
# Phase 2c: /ip/firewall/{filter,nat,raw} (ordered, comment-tag keyed).
#
# Ordered paths are managed by an embedded [salt:<tag>] comment; untagged rules
# are never touched. Bootstrap an existing device with `mikrotik.adopt` first,
# paste the emitted rules into pillar, then this renders the managed state.
# Every firewall apply should carry `confirm_timeout` (lockout safety net).
# Run dry-run first:
#   salt-sproxy --sync-all <device> state.apply mikrotik.firewall test=True
{%- set fw = salt['pillar.get']('mikrotik:firewall', {}) %}
{%- set al = fw.get('address_list', {}) %}
{%- if al.get('entries') %}
mikrotik_firewall_address_list:
  mikrotik.collection:
    - path: [ip, firewall, address-list]
    - entries: {{ al['entries'] | json }}
    - purge: {{ al.get('purge', False) | json }}
{%- if al.get('confirm_timeout') %}
    - confirm_timeout: {{ al['confirm_timeout'] }}
{%- endif %}
{%- endif %}

{#- Ordered firewall paths: filter, nat, raw. Each block is
    {confirm_timeout, purge, restrict, rules: [..]}. Rule content is managed;
    rule order is left as-is. #}
{%- for sub in ['filter', 'nat', 'raw'] %}
{%- set block = fw.get(sub, {}) %}
{%- if block.get('rules') %}
mikrotik_firewall_{{ sub }}:
  mikrotik.collection:
    - path: [ip, firewall, {{ sub }}]
    - entries: {{ block['rules'] | json }}
    - purge: {{ block.get('purge', False) | json }}
{%- if block.get('restrict') %}
    - restrict: {{ block['restrict'] | json }}
{%- endif %}
{%- if block.get('confirm_timeout') %}
    - confirm_timeout: {{ block['confirm_timeout'] }}
{%- endif %}
{%- endif %}
{%- endfor %}

{%- if not al.get('entries') and not fw.get('filter', {}).get('rules')
       and not fw.get('nat', {}).get('rules') and not fw.get('raw', {}).get('rules') %}
mikrotik_firewall_noop:
  test.succeed_without_changes:
    - name: "no mikrotik:firewall pillar data; nothing to manage"
{%- endif %}
