# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Antonio Huete Jimenez <tuxillo@quantumachine.net>
#
# Roll-up of all MikroTik config-management concerns so one explicit apply
# manages the whole device. Proxy minions are deliberately NOT wired into the
# global highstate (states/top.sls '*': base) -- those are Linux-minion states
# that would execute against the salt-01 host the proxy runs on. Apply this
# explicitly instead, dry-run first:
#   salt-sproxy --sync-all <device> state.apply mikrotik test=True
include:
  - mikrotik.system
  - mikrotik.addresses
  - mikrotik.dns
  - mikrotik.collections
  - mikrotik.firewall
