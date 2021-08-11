* Release 1.5.0
*** New Features
In February 2020 the BSV network underwent a hardfork known as the "Genesis Upgrade".
https://wiki.bitcoinsv.io/index.php/Genesis_upgrade

This release brings this library in line with the latest features from the Genesis upgrade.

- Genesis OpCode support in Script Interpreter (a number of OpCodes were re-enabled)
- New default limits on Script OpCodes (number of opcodes in script, size of script etc.)
- Expanded numeric support to cover BigIntegers in Script
- P2SH nuances w.r.t. simultaneous "soft-deprecation" of this feature.
- Backward-compatibility with pre-fork transactions (limits remaining in place)
- Full compatibility with BitcoinSV Node 1.0.8 Test Vectors

*** Notable Limits

Below are some notable constants delimiting new limits available to Script developers. 
These limits are all governed by Flags that can be passed to the Script Interpreter. 
```
//maximum size of push operation after Genesis
MAX_SCRIPT_ELEMENT_SIZE = 2147483647;  // 2Gigabytes after Genesis - (2^31 -1)

//maximum size of push operation before Genesis
MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520;

// Maximum number of non-push operations per script before GENESIS
MAX_OPS_PER_SCRIPT_BEFORE_GENESIS = 500;

// Maximum number of non-push operations per script after GENESIS
MAX_OPS_PER_SCRIPT_AFTER_GENESIS = UINT32_MAX // (4294967295L)

// Maximum script number length after Genesis
MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS = 750 * ONE_KILOBYTE;

//maximum size of numbers in Script before Genesis
MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS = 4;

```


* Release 1.4.1
*** New Features
New Locking / Unlocking Script Builders 
    - P2MSLock/UnlockBuilder - Pay to Multisig. This is naked MultiSig (the proper way to do multisig).
    - P2PKLock/UnlockBuilder - Pay to Public Key
    - P2SHLock/UnlockBuilder - Pay to Script Hash. This should be considered deprecated. Nodes support his for backwards compatibility only.
    - P2PKHDataLockBuilder - This is something new. Create a spendable data output.
    - UnspendableDataLockBuilder - OP_RETURN Data builder. Prepends a Transaction Output Script with OP_FALSE OP_RETURN followed by a series of data pushes.
    - SpendableDataLockBuilder - OP_DROP-style locking script builder. Allows creation of P2PKH-spendable data outputs. 
    - Added tests and fixes for Locking / Unlock builders

*** API Changes
    - Changed toASM / fromASM API to be in line with that generated / used by 'bsv' and 'dartsv' libraries.
    - Made some classes and constants public to be accessible when using the read-only lib
    - Modified the interface to use "getLockingScript()" and "getUnlockScript()" instead of scriptSig and scriptPubkey.

*** Bug Fixes 
    - Fixed a bug that prevented TransactionBuilder from creating any transactions that had no change output specified.
    - Bug fix for Transaction ID (bytes weren't reversed) and a new test to make sure the Transaction ID corresponds to its hash
    - Removed / Changed wrong or outdated code-comments.

-----------
