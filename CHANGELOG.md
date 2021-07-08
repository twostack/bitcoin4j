
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
