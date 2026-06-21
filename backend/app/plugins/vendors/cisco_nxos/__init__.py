"""Cisco NX-OS vendor plugin package (ADR-0025).

SSH-primary (netmiko ``cisco_nxos``) plugin mirroring ``cisco_ios`` with NX-OS
command text, NX-OS TextFSM templates, VRF-scoped collection, feature-gate
tolerance, and a ``configure replace`` baseline-replay config write path (same
tier as ``cisco_ios``; no NX-OS named-checkpoint primitive is used).
"""
