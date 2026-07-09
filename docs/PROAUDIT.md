# Production Readiness Audit

Act as a Staff Engineer performing a production readiness review of this repository.

Your job is NOT to immediately make changes.

## Objectives

Review the entire codebase and identify:

### 1. Functionality Issues

* Broken features
* Unhandled exceptions
* Missing validation
* API contract mismatches
* State management problems
* Async/concurrency issues
* Error handling gaps
* Dead code
* Security concerns

### 2. Code Quality

* Duplicate code
* Overly complex functions
* Architectural inconsistencies
* Naming issues
* Missing abstractions
* Technical debt
* Performance bottlenecks

### 3. UI/UX Review

* Visual inconsistencies
* Accessibility problems
* Poor layouts
* Mobile responsiveness issues
* Empty/loading/error states
* Animation and transition opportunities
* Component reuse opportunities
* Design system violations

### 4. Developer Experience

* Documentation gaps
* Missing tests
* CI/CD issues
* Environment configuration problems
* Build issues
* Dependency problems

### 5. Production Readiness

* Logging
* Monitoring hooks
* Error boundaries
* Security hardening
* Performance optimization
* Configuration management

## Deliverables

Produce a report only.

Create:

1. EXECUTIVE_SUMMARY.md
2. FUNCTIONAL_BUGS.md
3. UI_UX_IMPROVEMENTS.md
4. ARCHITECTURE_DEBT.md
5. PRODUCTION_READINESS.md

For every issue include:

* Severity (Critical/High/Medium/Low)
* File location
* Root cause
* Proposed fix
* Estimated effort
* Risk level

Do not modify code yet.
