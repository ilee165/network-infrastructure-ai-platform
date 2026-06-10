"""Shared fixture: a tmp mini-vault mirroring D:\\Brains\\Network-brain\\Network-infra-projects."""

from pathlib import Path

import pytest

from obsidian_mcp.vault import Vault

FOLDERS = [
    "00-Inbox",
    "01-Dashboard",
    "02-Projects",
    "03-Architecture",
    "04-Knowledge",
    "05-Vendors",
    "06-Runbooks",
    "07-Incidents",
    "08-Labs",
    "09-Reference",
    "10-Templates",
    "Assets",
    ".obsidian",
]

RUNBOOK_TEMPLATE = """# {{Runbook Name}}

## Summary

## Symptoms

## Impact

### User Impact

### Service Impact

## Scope

### Affected Systems

## Verification Steps

## Diagnostic Commands

### Cisco

## Expected Results

## Common Root Causes

## Troubleshooting Workflow

## Remediation Steps

## Validation

## Escalation Criteria

## References
"""

INCIDENT_TEMPLATE = """# Incident {{ID}}

## Summary

## Start Time

## End Time

## Impact

## Root Cause

## Timeline

## Systems Impacted

## Resolution

## Lessons Learned

## Prevention Actions

## Related
"""

KNOWLEDGE_TEMPLATE = """# {{Technology Name}}

## Definition

## Purpose

## Business Use Cases

## How It Works

## Key Components

## Architecture

### Logical Flow

## Design Considerations

## Advantages

## Disadvantages

## Common Failure Scenarios

## Troubleshooting

## Vendor Implementations

### Cisco

## Automation Opportunities

## Best Practices

## Related Technologies

## References
"""

PROJECT_TEMPLATE = """# {{Project Name}}

## Executive Summary

## Business Objective

## Current State

## Desired State

### Success Criteria

## Scope

### In Scope

### Out of Scope

## Requirements

## Assumptions

## Constraints

## Dependencies

## Architecture Overview

## Vendor Technologies

## Risks

## Implementation Plan

## Validation Plan

## Rollback Plan

## Lessons Learned

## Related Notes
"""

TEMPLATES = {
    "RUNBOOK_TEMPLATE.md": RUNBOOK_TEMPLATE,
    "NETWORK_INCIDENT_TEMPLATE.md": INCIDENT_TEMPLATE,
    "KNOWLEDGE_ARTICLE_TEMPLATE.md": KNOWLEDGE_TEMPLATE,
    "NETWORK_PROJECT_TEMPLATE.md": PROJECT_TEMPLATE,
}

BGP_NOTE = """---
created: 2026-01-15
tags: [routing]
---

# BGP

## Definition

Border Gateway Protocol is the path-vector routing protocol of the internet.

## Troubleshooting

Check neighbor state with show ip bgp summary. Flapping peers often mean MTU issues.
"""

OSPF_NOTE = """# OSPF

## Definition

Open Shortest Path First is a link-state IGP.

Mentions BGP redistribution exactly once: BGP.
"""


@pytest.fixture()
def vault_root(tmp_path: Path) -> Path:
    for folder in FOLDERS:
        (tmp_path / folder).mkdir()
    for name, text in TEMPLATES.items():
        (tmp_path / "10-Templates" / name).write_text(text, encoding="utf-8")
    (tmp_path / "04-Knowledge" / "BGP.md").write_text(BGP_NOTE, encoding="utf-8")
    (tmp_path / "04-Knowledge" / "OSPF.md").write_text(OSPF_NOTE, encoding="utf-8")
    (tmp_path / ".obsidian" / "hidden.md").write_text("# Hidden", encoding="utf-8")
    (tmp_path / "Assets" / "asset-note.md").write_text("# Asset", encoding="utf-8")
    return tmp_path


@pytest.fixture()
def vault(vault_root: Path) -> Vault:
    return Vault(vault_root)
