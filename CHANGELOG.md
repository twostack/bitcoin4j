#Release 1.6.4
### Second BugFix for Signature Generation

- When spending multiple outputs from the same transaction it was possible
  for some of the spending inputs to not get signed.
  This update fixes this bug. 

#Release 1.6.3
### BugFix for Signature Generation

- Bug was introduced by previous feature where spending and signing 
  multiple inputs resulted in invalid signatures being created. Fixed.
- Added additional testing via the Script Interpreter to verify that 
  signatures don't break and that utxos are spent correctly. 

#Release 1.6.2
### Foot-in-mouth release

I forgot to make the TransactionSigner's constructor public. *facepalm*. 

#Release 1.6.1
### TransactionBuilder Signature API Completion

Version 1.6.0 introduces the new API for passing a 
TransactionSigner to the TransactionBuilder.spendFromTransaction()
method. 

This update completes the shape of that API by doing the same for : 
* TransactionBuilder.spendFromOutpoint()
* TransactionBuilder.spendFromOutput()
* TransactionBuilder.spendFromUtxoMap()

#Release 1.6.0
### TransactionBuilder Signature generation refactor

Transaction building suffered from a rather pernicious problem  
wherein it becomes hard/complicated to calculate fees.  
This stems from the fact that when you try to large number of  
utxos, the consequent large number of inputs in the spending tx  
leads to guesswork about the appropriate fee calculation.  

This update refactors the process of Transaction Signing so that  
the builder can directly generate the signed inputs and therefore  
perform the work of fee calculation internally.  

Please see the transaction/TransactionBuilderTest.java for an example use.  

# Release 1.5.5
Made constructors public so to allow outside-package subclassing

Locking script & tx spending fixes:
- The spendFromTransaction() fundion in TransactionBuilder was using the
  incorrect endian encoding the for the transactionID. Fixed.
- The P2PKHDataLockBuilder had a broken means for validating
  the script template. fixed.
- Added hashcode and equals to TransactionOutpoint so it can used in
  collections

P2PKH Bugfix in template check

Javadoc fixes: 
- Fixed javadocs for sha256 utility
- Fixed javadocs for private key crypto
- Fixed up ECKey constructor javadocs
- Fixed javadocs for Monetary
- Fixed javadocs for base58 encoder
- Fixed javadocs for legacy addresses
- Added javadoc entries for TransactionBuilder

Allow zero-satoshi outputs for OP_RETURN data
expose the Change Output of the Builder

Refactored change API in TransactionBuilder

- setting change in the TransactionBuilder is split into
  implicit P2PKH when address is provided and explicit
  locking script builder.

Factored out pre-image signing

Added local state to TransactionSigner:
- Not the most elegant solution. Ideally the sign() method should return
  structured data with actual signature information.
  Instead, to not break the API for this method the internal state of the
  class now reflects additional data after signing.

added documentation for getPrevoutsHash() because it's non-obvious from name

Made public some previously protected byte array reader methods

Added toAsmString() method

# Release 1.5.0

### New Features
In February 2020 the BSV network underwent a hardfork known as the "Genesis Upgrade".
https://wiki.bitcoinsv.io/index.php/Genesis_upgrade

This release brings this library in line with the latest features from the Genesis upgrade.

- Genesis OpCode support in Script Interpreter (a number of OpCodes were re-enabled)
- New default limits on Script OpCodes (number of opcodes in script, size of script etc.)
- Expanded numeric support to cover BigIntegers in Script
- P2SH nuances w.r.t. simultaneous "soft-deprecation" of this feature.
- Backward-compatibility with pre-fork transactions (limits remaining in place)
- Full compatibility with BitcoinSV Node 1.0.8 Test Vectors

### Notable Limits

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


# Release 1.4.1
### New Features
New Locking / Unlocking Script Builders 
    - P2MSLock/UnlockBuilder - Pay to Multisig. This is naked MultiSig (the proper way to do multisig).
    - P2PKLock/UnlockBuilder - Pay to Public Key
    - P2SHLock/UnlockBuilder - Pay to Script Hash. This should be considered deprecated. Nodes support his for backwards compatibility only.
    - P2PKHDataLockBuilder - This is something new. Create a spendable data output.
    - UnspendableDataLockBuilder - OP_RETURN Data builder. Prepends a Transaction Output Script with OP_FALSE OP_RETURN followed by a series of data pushes.
    - SpendableDataLockBuilder - OP_DROP-style locking script builder. Allows creation of P2PKH-spendable data outputs. 
    - Added tests and fixes for Locking / Unlock builders

#### API Changes
    - Changed toASM / fromASM API to be in line with that generated / used by 'bsv' and 'dartsv' libraries.
    - Made some classes and constants public to be accessible when using the read-only lib
    - Modified the interface to use "getLockingScript()" and "getUnlockScript()" instead of scriptSig and scriptPubkey.

#### Bug Fixes 
    - Fixed a bug that prevented TransactionBuilder from creating any transactions that had no change output specified.
    - Bug fix for Transaction ID (bytes weren't reversed) and a new test to make sure the Transaction ID corresponds to its hash
    - Removed / Changed wrong or outdated code-comments.

-----------
