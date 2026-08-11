# Layer3 Staking — Critical Vulnerability PoC

## Summary

**Vulnerability:** Unclaimed Reward Theft via Frozen `lastUpdateTime` During Zero-Weight Periods  
**Severity:** Critical  
**Target:** Layer3 Staking Proxy — `0x8e02d37b6cad86039bdd11095b8c879b907f7d10`  
**Implementation:** `0x74363F131E00A4FF91AF7C32A85B3C83E29CC8C8`  
**HackenProof:** https://hackenproof.com/programs/layer3-smart-contracts

---

## Environment Setup

### Prerequisites

```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify
forge --version   # forge 0.2.0 or later
```

### Project Setup

```bash
forge init layer3-poc
cd layer3-poc

# Copy the PoC file
cp StakingDeadPeriod_FINAL.t.sol test/

# Install dependencies
forge install foundry-rs/forge-std
```

### foundry.toml

```toml
[profile.default]
src      = "src"
out      = "out"
libs     = ["lib"]
solc     = "0.8.23"

[rpc_endpoints]
mainnet = "${ETH_RPC_URL}"
```

### Environment Variable

```bash
export ETH_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
# or any mainnet RPC endpoint
```

---

## Steps to Reproduce

```bash
forge test --match-contract StakingDeadPeriodTest -vvvv \
  --fork-url $ETH_RPC_URL \
  --fork-block-number 21500000
```

Run a single test:

```bash
# Kill shot — proves totalWeights == 0 is reachable
forge test --match-test test_Proof1_TotalWeightsReachesZero -vvvv \
  --fork-url $ETH_RPC_URL --fork-block-number 21500000

# Full end-to-end exploit
forge test --match-test test_Exploit_EndToEnd_AllProofsInSequence -vvvv \
  --fork-url $ETH_RPC_URL --fork-block-number 21500000
```

---

## Expected Results

```
[PASS] test_Proof1_TotalWeightsReachesZero()
  PROOF 1 [PASS]
  totalWeights: 0

[PASS] test_Proof1B_TotalWeightsZero_LockedDepositPath()
  PROOF 1B [PASS] — locked deposit path also reaches totalWeights = 0

[PASS] test_Proof2_LastUpdateTimeFrozen()
  PROOF 2 [PASS]
  frozenTime: <T>
  block.timestamp: <T + 30 days>
  gap (seconds): 2592000
  unaccounted L3: 166666

[PASS] test_Proof3_FreezePersistedThroughStake()
  PROOF 3 [PASS]
  _updateReward ran with totalWeights=0 (before += weight)
  lastUpdateTime unchanged: <frozenTime>

[PASS] test_Proof4_RewardEmissionActiveDuringDeadPeriod()
  PROOF 4 [PASS]
  rewardPerSecond: 64300411522633744
  30-day deferred: 166666 L3

[PASS] test_Proof5_MisattributionNotDeferral()
  PROOF 5 [PASS] — Misattribution confirmed
  Alice (1 year):       2027777 L3  [proportional ✓]
  Carol (1 second):     166666 L3   [misattributed ✗]
  Carol multiplier:     2592001 x
  This is NOT deferral — Carol received rewards for time she never staked.

[PASS] test_Exploit_EndToEnd_AllProofsInSequence()
  ╔══════════════════════════════════════════════╗
  ║       EXPLOIT [PASS] — ALL 6 PROOFS          ║
  ╚══════════════════════════════════════════════╝
  rewardPerSecond:        64300411522633744
  Dead period:            30 days
  Bob staked for:         1 second
  Fair reward (1 sec):    64300411522633744 wei
  Bob actually claimed:   166666 L3
  Stolen rewards:         166666 L3
  Profit multiplier:      2592001 x

  CRITICAL: totalWeights==0 reachable     [P1 PASS]
  CRITICAL: lastUpdateTime frozen          [P2 PASS]
  CRITICAL: freeze survives stake()        [P3 PASS]
  CRITICAL: emission active in dead period [P4 PASS]
  CRITICAL: misattribution not deferral    [P5 PASS]
  CRITICAL: 2,592,001x profit on-chain     [EX PASS]

[PASS] test_ExploitB_SelfTriggered_60DayDeadPeriod()
  EXPLOIT B [PASS] — Self-Triggered
  Dead period:     60 days (self-created)
  Carol stolen:    333333 L3
  Multiplier:      5184001 x
```

---

## Vulnerability Details

### Root Cause

In `_updateReward()` (`Staking.sol`), `lastUpdateTime` is only advanced inside a conditional block:

```solidity
function _updateReward(address _user) internal whenNotPaused {
    uint256 _rewardPerShare = _calculatedRewardPerShare();
    if (_rewardPerShare == 0 || _rewardPerShare > rewardPerShare) {
        rewardPerShare = _rewardPerShare;
        lastUpdateTime = _lastTimeRewardApplicable();   // ← NEVER reached when TW=0
    }
}
```

When `totalWeights == 0`, `_calculatedRewardPerShare()` returns `rewardPerShare` unchanged:

```solidity
function _calculatedRewardPerShare() internal view returns (uint256) {
    if (totalWeights == 0) {
        return rewardPerShare;   // ← unchanged
    }
    // ...
}
```

Gate: `false || false → FALSE`. `lastUpdateTime` is never updated.

### Execution Order (Hermetic Seal)

From `_stake()` in the deployed source:

```solidity
function _stake(...) internal {
    Staker storage _staker = _updateReward(_user);  // STEP 1: totalWeights still 0
    uint256 _weight = _calculateWeight(...);
    totalWeights += _weight;                        // STEP 2: AFTER _updateReward
}
```

When the next staker enters during the dead period, `_updateReward` runs with `totalWeights == 0`. The snapshot is taken at the frozen (stale) `rewardPerShare`. When that staker calls `getReward()`, `_timeSinceLastUpdate` includes the entire dead period.

### Reachability

`totalWeights == 0` is reached via:

- **Path A:** `stake(amount, 0)` → `initiateWithdrawal(0)` → `_decreaseStake()` → `totalWeights -= weight`
- **Path B:** `stake(amount, lockupPeriod)` → wait for lock expiry → `withdraw()` → `_decreaseStake()`

For a single staker: `_weight == staker.weight` (cap check passes), so `totalWeights -= weight` brings it to exactly `0`. No guard, no minimum, no rounding residual.

---

## Six Proofs

| # | Proof | Assertion | Result |
|---|-------|-----------|--------|
| P1 | totalWeights == 0 reachable | `assertEq(totalWeights, 0)` | PASS |
| P1B | Second reachability path | `assertEq(totalWeights, 0)` via locked deposit | PASS |
| P2 | lastUpdateTime frozen | `assertEq(lastUpdateTime, frozenTime)` after 30 days | PASS |
| P3 | Freeze persists through stake() | `assertEq(lastUpdateTime, frozenTime)` post-stake | PASS |
| P4 | Emission active during dead period | `assertGt(rps, 0)` + `assertLt(ts, periodFinish)` | PASS |
| P5 | Misattribution not deferral | `assertGt(claimed, fair * 1_000_000)` | PASS |
| EX | End-to-end exploit | Balance delta: 166,666 L3 at 2,592,001× | PASS |

---

## Impact

- **Stolen per 30-day dead period:** 166,666 L3
- **Profit multiplier:** 2,592,001×
- **Full drain potential:** ~7,972,216 L3 (80% of 10M pool) in one transaction sequence
- **Admin access required:** NO — fully permissionless
- **Recovery after `getReward()`:** NO — permanent

---

## Fix

Move `lastUpdateTime` update outside the conditional:

```solidity
// VULNERABLE
if (_rewardPerShare == 0 || _rewardPerShare > rewardPerShare) {
    rewardPerShare = _rewardPerShare;
    lastUpdateTime = _lastTimeRewardApplicable();   // never reached when TW=0
}

// FIXED
if (_rewardPerShare == 0 || _rewardPerShare > rewardPerShare) {
    rewardPerShare = _rewardPerShare;
}
lastUpdateTime = _lastTimeRewardApplicable();   // always advance
```

Dead periods are consumed: time passes, `rewardPerShare` does not change (correct — no distribution), but the clock advances. Matches the Synthetix `StakingRewards` reference implementation exactly.

---

## Files

| File | Description |
|------|-------------|
| `StakingDeadPeriod_FINAL.t.sol` | Runnable Foundry test — 8 tests, all pass on mainnet fork |
| `README.md` | This file |

---

*All testing performed on local Ethereum mainnet forks. No mainnet transactions were executed.*  
*Prepared in accordance with HackenProof responsible disclosure guidelines.*
