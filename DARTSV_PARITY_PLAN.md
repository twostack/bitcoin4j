# DartSV Parity Plan for bitcoin4j

Tracking document for bringing bitcoin4j into feature parity with dartsv.

---

## Stream 1: Bug Fixes & Interpreter Hardening
**Status: COMPLETE**

- [x] Stack operation fixes — OP_PICK, OP_ROLL, OP_DUP, OP_NIP, OP_OVER, OP_ROT, OP_TUCK now use `.clone()` to properly copy stack items
- [x] OP_CAT implementation with bounds checking (520-byte pre-Genesis limit)
- [x] OP_NUM2BIN implementation with sign bit handling and padding
- [x] OP_LSHIFT/OP_RSHIFT implementations with proper shift masking
- [x] SigHash ForkID handling
- [x] OP_CODESEPARATOR stripping — `removeCodeseparators()` for legacy, `stripUptoFirstCodeSep()` for ForkID
- [x] VarInt encoding fixes

**Commits:** `dc1b0ce` (Various interpreter fixes), `6e3f950` (CODE_SEP Updates)

---

## Stream 2: Dedicated PreImage Generator
**Status: COMPLETE**

- [x] `getSighashPreimage()` method for preimage extraction
- [x] `sigHashForForkid()` — separate ForkID-specific preimage generation
- [x] OP_CODESEPARATOR handling — legacy strips all, ForkID strips before first
- [x] Both legacy and ForkID preimage generation paths

---

## Stream 3: Script Template System
**Status: COMPLETE**

- [x] `ScriptTemplate` interface — `getName()`, `matches()`, `canBeSatisfiedBy()`, `extractScriptInfo()`
- [x] `ScriptInfo` abstract base class with typed subclasses
- [x] `ScriptTemplateRegistry` singleton — `identifyScript()`, `extractScriptInfo()`, `register()`
- [x] P2PKHTemplate + P2PKHScriptInfo
- [x] P2PKTemplate + P2PKScriptInfo
- [x] P2MSTemplate + P2MSScriptInfo
- [x] P2SHTemplate + P2SHScriptInfo
- [x] OpReturnTemplate + OpReturnScriptInfo
- [x] HodlockerTemplate + HodlockerScriptInfo
- [x] AuthorIdentityTemplate + AuthorIdentityScriptInfo
- [x] BProtocolTemplate + BProtocolScriptInfo
- [x] HodlLockBuilder + HodlUnlockBuilder (transaction package)
- [x] Tests for registry and all 8 templates

---

## Stream 4: Unsigned Tx Change Output Support
**Status: COMPLETE**

- [x] Change output construction works on unsigned transaction builds
- [x] `sendChangeTo(Address)` and `sendChangeTo(LockingScriptBuilder)` methods

**Commit:** `d764607` (Configurable Transaction Version numbers)

---

## Stream 5: Chronicle Upgrade
**Status: COMPLETE**

### 5a: Chronicle Opcodes (10 new opcodes)
**Status: COMPLETE**

**Files modified:** `Interpreter.java`, `ScriptOpCodes.java`, `ScriptFlags.java`, `Script.java`

- [x] Add `SCRIPT_ENABLE_CHRONICLE` flag to `ScriptFlags.java`
- [x] Add `AFTER_CHRONICLE` verify flag to `Script.java` VerifyFlag enum
- [x] Register new opcodes in `ScriptOpCodes.java`:
  - [x] OP_SUBSTR (0xB3 / 179)
  - [x] OP_LEFT (0xB4 / 180)
  - [x] OP_RIGHT (0xB5 / 181)
  - [x] OP_LSHIFTNUM (0xB6 / 182)
  - [x] OP_RSHIFTNUM (0xB7 / 183)
  - [x] OP_2MUL (0x8D / 141) — re-enabled post-Chronicle
  - [x] OP_2DIV (0x8E / 142) — re-enabled post-Chronicle
  - [x] OP_VER (0x62 / 98) — re-enabled post-Chronicle
  - [x] OP_VERIF (0x65 / 101) — re-enabled post-Chronicle
  - [x] OP_VERNOTIF (0x66 / 102) — re-enabled post-Chronicle
- [x] Implement opcode logic in `Interpreter.java`, all gated behind `AFTER_CHRONICLE`:
  - [x] OP_SUBSTR — extract substring by start index and length
  - [x] OP_LEFT — extract leftmost N bytes
  - [x] OP_RIGHT — extract rightmost N bytes
  - [x] OP_LSHIFTNUM — left shift by numeric value
  - [x] OP_RSHIFTNUM — right shift by numeric value
  - [x] OP_2MUL — multiply top stack item by 2
  - [x] OP_2DIV — divide top stack item by 2
  - [x] OP_VER — push transaction version to stack
  - [x] OP_VERIF — conditional branch if tx version >= N
  - [x] OP_VERNOTIF — conditional branch if tx version < N
- [x] Update `isInvalidBranchingOpcode()` to accept verifyFlags parameter
- [x] Update `isOpcodeDisabled()` for Chronicle-aware enablement

**Test:** `ChronicleOpcodesTest.java` — 17 tests

### 5b: MAX_SCRIPT_NUM_LENGTH Increase
**Status: COMPLETE**

- [x] Add Chronicle-specific constant: `MAX_SCRIPT_NUM_LENGTH_AFTER_CHRONICLE = 32 * 1024 * 1024` (32MB)
- [x] Chronicle opcodes use 32MB limit for numeric operations

### 5c: Malleability Check Relaxation
**Status: COMPLETE**

- [x] Skip 7 malleability flags when transaction version > 1 and AFTER_CHRONICLE:
  - [x] SIGPUSHONLY
  - [x] CLEANSTACK
  - [x] MINIMALDATA
  - [x] MINIMALIF
  - [x] LOW_S
  - [x] NULLFAIL
  - [x] NULLDUMMY
- [x] Maintain enforcement for v1 transactions

**Test:** `ChronicleMalleabilityTest.java` — 2 tests

### 5d: SIGHASH_CHRONICLE (0x20)
**Status: COMPLETE**

- [x] Add `SIGHASH_CHRONICLE(0x20)` to `SigHashType.java`
- [x] Update `SigHashType.hasValue()` to use bitmask logic
- [x] Add `hasChronicle()` method to `TransactionSignature.java`
- [x] Add `calcSigHashValue()` overload with Chronicle parameter
- [x] Update `checkSignatureEncoding()` — Chronicle flag exempts ForkID requirement
- [x] Implement SIGHASH_CHRONICLE preimage generation in `SigHash.java`:
  - [x] scriptCode derived from locking script for OP_CHECKSIG in v2+ txs
  - [x] Support both legacy/OTDA and ForkID digest algorithms
  - [x] `afterChronicle` boolean gates interpretation of bit 0x20 (backward compatible)
- [x] Update `Interpreter.java` `executeScript()` to accept optional lockingScript parameter
- [x] Thread lockingScript through `executeCheckSig()` and `executeMultiSig()`
- [x] `correctlySpends()` passes `scriptPubKey` as lockingScript when AFTER_CHRONICLE

**Test:** `ChronicleSighashTest.java` — 13 tests

---

## Stream 6: Error Diagnostics & Tracing
**Status: COMPLETE**

**Files modified:** `Interpreter.java`, `ScriptException.java`, new `ScriptTraceCallback.java`

- [x] Add `ScriptTraceCallback` interface for step-by-step script execution debugging
  - [x] Callback receives: opcode, opcode name, stack state, alt-stack state, program counter
- [x] Wire trace callback into `executeScript()` loop in `Interpreter.java`
  - [x] New overload: `executeScript(..., ScriptTraceCallback traceCallback)`
- [x] Improve OP_SPLIT error messages — include hex values, position, and data length
- [x] Improve OP_EQUALVERIFY error messages — include hex values of compared items and byte counts
- [x] Add `toString()` override to `ScriptException.java` with error code, message, and cause

**Tests:** `ScriptTraceCallbackTest.java` — 4 tests, `ScriptDiagnosticsTest.java` — 4 tests

---

## Execution Order & Dependencies

```
Stream 1 (DONE) ──┐
Stream 2 (DONE) ──┤
                   ├──→ Stream 3 (DONE) ──┐
                   │    Stream 4 (DONE) ──┤
                   │                       ├──→ Stream 5 (DONE)
                   │                       │    Stream 6 (DONE)
                   │                       │
```

## Remaining Work Summary

| Stream | Items | Status |
|--------|-------|--------|
| **5d** SIGHASH_CHRONICLE preimage | SigHash.java preimage generation + executeScript lockingScript param | **Complete** |
| **6** Diagnostics & Tracing | Trace callback + error improvements | **Complete** |
