"""Vendor package for VMware vSphere (``vmware``, ADR-0051).

Vendor-private pyVmomi (SOAP) client + read-only virtualization-inventory
plugin. Mutually independent of every other vendor package (REPO-STRUCTURE
§3.2). No write path (ADR-0051 §3).
"""
