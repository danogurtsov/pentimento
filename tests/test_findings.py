from pentimento.detection.findings import parse_findings


def test_parses_a_finding_in_the_literal_spec_format() -> None:
    raw = """
### [F-1] Reentrancy in withdraw()
Severity: Critical  |  Confidence: 90%
Location: Vault.sol#L40-L55, withdraw()
Root Cause: State is written after the external call, allowing reentrant withdrawal.
Exploit: 1. Deposit 2. Call withdraw() 3. Reenter from the token's callback
Impact: An attacker can drain the full vault balance.
Fix: Use the checks-effects-interactions pattern; move the state write before the call.
PoC: forge test showing a reentrant withdraw draining more than deposited.
"""
    findings = parse_findings(raw)

    assert len(findings) == 1
    f = findings[0]
    assert f.id == "F-1"
    assert f.title == "Reentrancy in withdraw()"
    assert f.severity == "Critical"
    assert f.confidence == 90
    assert f.location == "Vault.sol#L40-L55, withdraw()"
    assert "written after the external call" in f.root_cause
    assert "Deposit" in f.exploit
    assert "drain the full vault balance" in f.impact
    assert "checks-effects-interactions" in f.fix
    assert f.poc is not None and "forge test" in f.poc


def test_parses_multiple_findings_independently() -> None:
    raw = """
### [F-1] First bug
Severity: High  |  Confidence: 80%
Location: A.sol#L1, f()
Root Cause: root cause one here now
Exploit: step one two three
Impact: impact one
Fix: fix one

### [F-2] Second bug
Severity: Low  |  Confidence: 30%
Location: B.sol#L2, g()
Root Cause: root cause two here now
Exploit: step four five six
Impact: impact two
Fix: fix two
"""
    findings = parse_findings(raw)

    assert [f.id for f in findings] == ["F-1", "F-2"]
    assert findings[0].title == "First bug"
    assert findings[1].title == "Second bug"
    assert "impact one" in findings[0].impact
    assert "impact two" in findings[1].impact


def test_a_clean_response_with_no_findings_returns_an_empty_list() -> None:
    assert parse_findings("No findings. This unit looks clean.") == []


def test_poc_is_none_when_absent_not_an_empty_string() -> None:
    raw = """
### [F-1] Low severity issue
Severity: Low  |  Confidence: 20%
Location: A.sol#L1, f()
Root Cause: minor issue here now
Exploit: step one two three
Impact: minor impact
Fix: minor fix
"""
    findings = parse_findings(raw)
    assert findings[0].poc is None


def test_parses_real_model_output_shape_with_bold_markdown_and_grouped_fields() -> None:
    # verbatim excerpt from a real --route run against EulerEarn's PublicAllocator.sol -
    # Severity+Confidence share one line, Location is bold-labeled on its own line - a real
    # shape the literal prompt template doesn't show, see findings.py's own module docstring.
    raw = """
### [F-1] setFlowCaps Front-Running — Caps Overwrite During Reallocation
**Severity: Medium** | **Confidence: 90%**
**Location:** `setFlowCaps()` L73–78; `reallocateTo()` L106–115

**Root Cause:**
`setFlowCaps()` **overwrites** `flowCaps[vault][id]` with direct assignment, ignoring any
concurrent modifications from `reallocateTo()`.

**Exploit (5 steps):**
1. Admin intends a lower cap
2. User front-runs with reallocateTo()
3. User's tx executes first
4. Admin's tx resets the cap
5. Net result exceeds the intended limit

**Impact:**
Caps become meaningless under concurrent admin/user interaction.

**Fix:**
Merge caps instead of overwriting, or add a lock around cap-modifying operations.
"""
    findings = parse_findings(raw)

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "Medium"
    assert f.confidence == 90
    assert "setFlowCaps()" in f.location
    assert "overwrites" in f.root_cause
    assert "front-run" in f.exploit.lower()
    assert "meaningless" in f.impact
    assert "Merge caps" in f.fix
    assert f.poc is None
