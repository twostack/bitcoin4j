package org.twostack.bitcoin.transaction;

import org.twostack.bitcoin.Utils;

import java.io.IOException;
import java.nio.ByteBuffer;

public class TransactionSignature {


    private byte[] signatureBytes;
    int _nHashType;

    public TransactionSignature(byte[] sigBytes, int hashType ){
        this.signatureBytes = sigBytes;
        this._nHashType = hashType;
    }

    public static TransactionSignature fromTxFormat(byte[] sigBytes) {

        int nhashtype = sigBytes[sigBytes.length - 1];
        byte[] signatureBytes = new byte[sigBytes.length - 1];

        ByteBuffer byteBuffer = ByteBuffer.wrap(sigBytes);
        byteBuffer.get(signatureBytes, 0, sigBytes.length - 1);

        return new TransactionSignature(signatureBytes, nhashtype);
    }

    public static TransactionSignature fromTxFormat(String encode) {

        byte[] bytes = Utils.HEX.decode(encode);

        return fromTxFormat(bytes);
    }

    public byte[] getSignatureBytes() {
        return signatureBytes;
    }


    public byte[] toTxFormat() throws IOException {
        //return HEX encoded transaction Format

        WriteUtils wu = new WriteUtils();

        wu.writeBytes(signatureBytes, signatureBytes.length);

        wu.writeUint8LE(_nHashType);

        return wu.getBytes();
    }
}
