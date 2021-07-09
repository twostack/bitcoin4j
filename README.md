# Introduction
![Java CI](https://github.com/twostack/bitcoin4j/workflows/Java%20CI%20with%20Gradle/badge.svg)

## Overview

Bitcoin4J is a Bitcoin library for the Java Language licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.txt).  

This library has been built in line with the ideals espoused by [BitcoinSV](https://bitcoinsv.io), 
i.e. massive on-chain scaling, protocol stability and original-bitcoin-protocol implementation.

### Learn More about BitcoinSV
You can learn more about BitcoinSV by visiting : 
* [TwoStack Bitcoin Developer Guide](https://www.twostack.org/docs/getting-started/)
* [TwoStack Youtube Channel](https://youtube.com/twostack)
* [Bitcoin Association Website](https://bitcoinsv.io) 
* [BitcoinSV Wiki](https://wiki.bitcoinsv.io/).

## Installation
Binaries for the library are [available on Maven Central](https://search.maven.org/artifact/org.twostack/bitcoin4j/1.4.1/jar). 


### Gradle Dependencies
```gradle
implementation("org.twostack:bitcoin4j:1.4.1")
```

### Maven Dependencies
```xml
<dependency>
  <groupId>org.twostack</groupId>
  <artifactId>bitcoin4j</artifactId>
  <version>1.4.1</version>
</dependency>
```

## Clean Transaction Builder
Several helper classes and APIs exist to make constructing Transactions more intuitive.

[See the full example source code](https://github.com/twostack/data-transaction/blob/main/src/main/kotlin/main.kt)

As a native Java implementation, the library integrates well with other JVM languages, e.g. Kotlin. 
```kotlin
    val txBuilder: TransactionBuilder = TransactionBuilder()
    val spendingTx: Transaction = txBuilder.spendFromTransaction(aliceFundingTx, 1, Transaction.NLOCKTIME_MAX_VALUE, unlockBuilder)
        .spendTo(bobLockingBuilder, BigInteger.valueOf(10000))
        .sendChangeTo(aliceAddress, aliceLockingBuilder)
        .withFeePerKb(512)
        .build(true)
```

## Features

* Unbounded Transaction Types (creating non-standard transactions)
* HD Key Derivation \(BIP32\)
* Mnemonic Seed Support \(BIP39\)
* Original Bitcoin Address format 
* A built-in Bitcoin Script Interpreter
* Custom-Script Builder Interface to support novel locking/spending conditions within Script
    * P2PKH Transaction Builder - Pay to Pubkey Hash standard Transactions 
    * P2MS Transaction Builder - Pay to Multisig. This is naked MultiSig (the proper way to do multisig).
    * P2PK Transaction Builder - Pay to Public Key standard Transactions
    * P2SH Transaction Builder - Pay to Script Hash. This should be considered deprecated. BitcoinSV Nodes support this for backwards compatibility only.
    * P2PKHDataLockBuilder - This is something new. Create a spendable data output. Spendable using P2PKH Transaction. 
    * UnspendableDataLockBuilder - OP_RETURN-style Data builder. Prepends a Transaction Output Script with OP_FALSE OP_RETURN followed by a series of data pushes.

### Deprecated Features
The following features represent forks away from the original Bitcoin Protocol.

This library lacks, and does not implement :

* Segregated Witness \(Segwit\) Transaction support (Bitcoin Core - BTC)
* Schnorr Transaction Signature support (Bitcoin Cash - BCH)
* Check Datasig \(OP\_CHECKDATASIG\) (Bitcoin Cash - BCH)
* Taproot (Bitcoin Core - BTC)

## Acknowledgement

This library is a fork of the BitcoinJ and BitcoinJ-Cash projects. Contributor acknowledgements have been preserved in the AUTHORS file.  

## Contact

You can reach the author at : stephan@twostack.org
