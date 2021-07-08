# Introduction
![Java CI](https://github.com/twostack/bitcoin4j/workflows/Java%20CI%20with%20Gradle/badge.svg)

## Overview

Bitcoin4J is a Bitcoin library for the Java Language licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt).  

This library has been built in line with the ideals espoused by [BitcoinSV](https://bitcoinsv.io), 
i.e. massive on-chain scaling, protocol stability and original-bitcoin-protocol implementation.

### Learn More about BitcoinSV
You can learn more about BitcoinSV by visiting : 
* [TwoStack Bitcoin Developer Guide](https://www.twostack.org/docs/getting-started/)
* [Bitcoin Association Website](https://bitcoinsv.io) 
* [BitcoinSV Wiki](https://wiki.bitcoinsv.io/).

## Feature Support

This library lacks, and will not implement :
* Segregated Witness \(Segwit\) Transaction support
* Schnorr Transaction Signature support 
* Check Datasig \(OP\_CHECKDATASIG\) 
* Taproot 

Current Supported features are :
* Unbounded Transaction Types (creating non-standard transactions)
* HD Key Derivation \(BIP32\)
* Mnemonic Seed Support \(BIP39\)
* Original Bitcoin Address format 
* A built-in Bitcoin Script Interpreter
* Custom-Script Builder Interface to support novel locking/spending conditions within Script
    * P2PKH Transaction Builder - Pay to Pubkey Hash standard Transactions 
    * P2MS Transaction Builder - Pay to Multisig. This is naked MultiSig (the proper way to do multisig).
    * P2PK Transaction Builder - Pay to Public Key standard Transactions
    * P2SH Transaction Builder - Pay to Script Hash. This should be considered deprecated. Nodes support his for backwards compatibility only.
    * P2PKHDataLockBuilder - This is something new. Create a spendable data output. Spendable using P2PKH Transaction. 
    * UnspendableDataLockBuilder - OP_RETURN-style Data builder. Prepends a Transaction Output Script with OP_FALSE OP_RETURN followed by a series of data pushes.

## Acknowledgement

This library is a fork of the BitcoinJ and BitcoinJ-Cash projects. Contributor acknowledgements have been preserved in the AUTHORS file.  

## Contact

You can reach the author at :

* @beardpappa on Twitter
* beardpappa@moneybutton.com \(PayMail to buy me a beer\)
* stephan@twostack.org

