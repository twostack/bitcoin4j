package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.Utils;

public class TransactionSignature {

    byte[] signatureBytes;

    private TransactionSignature(byte[] sigBytes){
        this.signatureBytes = sigBytes;
    }
    public static TransactionSignature fromTxFormat(String encode) {

        return new TransactionSignature(Utils.HEX.decode(encode));
    }
}
