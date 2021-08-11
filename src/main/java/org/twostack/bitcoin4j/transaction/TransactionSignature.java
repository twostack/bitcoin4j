
/*
 * Copyright 2021 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.twostack.bitcoin4j.transaction;

import com.google.common.base.Preconditions;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.VerificationException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * A TransactionSignature wraps an {@link ECKey.ECDSASignature} and adds methods for handling
 * the additional SIGHASH mode byte that is used.
 */
public class TransactionSignature extends ECKey.ECDSASignature {

    /**
     * A byte that controls which parts of a transaction are signed. This is exposed because signatures
     * parsed off the wire may have sighash flags that aren't "normal" serializations of the enum values.
     * Because Bitcoin Core works via bit testing, we must not lose the exact value when round-tripping
     * otherwise we'll fail to verify signature hashes.
     */
    public final int sighashFlags;



/**
 * A TransactionSignature wraps an {@link ECKey.ECDSASignature} and adds methods for handling
 * the additional SIGHASH mode byte that is used.
 */


    /** Constructs a signature with the given components and SIGHASH_ALL. */
    public TransactionSignature(BigInteger r, BigInteger s) {
        this(r, s, SigHashType.ALL.value);
    }

    /** Constructs a signature with the given components and raw sighash flag bytes (needed for rule compatibility). */
    public TransactionSignature(BigInteger r, BigInteger s, int sighashFlags) {
        super(r, s);
        this.sighashFlags = sighashFlags;
    }


    public TransactionSignature(ECKey.ECDSASignature signature, SigHashType mode, boolean anyoneCanPay, boolean useForkId) {
        super(signature.r, signature.s);
        sighashFlags = calcSigHashValue(mode, anyoneCanPay, useForkId);
    }

    /** Constructs a transaction signature based on the ECDSA signature. */
    public TransactionSignature(ECKey.ECDSASignature signature, SigHashType mode, boolean anyoneCanPay) {
        super(signature.r, signature.s);
        sighashFlags = calcSigHashValue(mode, anyoneCanPay);
    }

    public static TransactionSignature fromTxFormat(byte[] sigBytes) throws SignatureDecodeException {

        //allow empty signatures
        if (sigBytes.length == 0){
            return new TransactionSignature(BigInteger.ONE, BigInteger.ONE, 1);
        }

        int nhashtype = sigBytes[sigBytes.length - 1] & 0xFF; //cast to unsigned byte value

        byte[] signatureBytes = new byte[sigBytes.length - 1];

        ByteBuffer byteBuffer = ByteBuffer.wrap(sigBytes);
        byteBuffer.get(signatureBytes, 0, sigBytes.length - 1);


        ECKey.ECDSASignature sig = ECKey.ECDSASignature.decodeFlexDER(signatureBytes, false);

        return new TransactionSignature(sig.r, sig.s, nhashtype);

    }

    public static TransactionSignature fromTxFormat(String encode) throws SignatureDecodeException {

        byte[] bytes = Utils.HEX.decode(encode);

        return fromTxFormat(bytes);
    }


    /** Calculates the byte used in the protocol to represent the combination of mode and anyoneCanPay. */
    public static int calcSigHashValue(SigHashType mode, boolean anyoneCanPay) {
        Preconditions.checkArgument(SigHashType.ALL == mode || SigHashType.NONE == mode || SigHashType.SINGLE == mode); // enforce compatibility since this code was made before the SigHash enum was updated
        int sighashFlags = mode.value;
        if (anyoneCanPay)
            sighashFlags |= SigHashType.ANYONECANPAY.value;
        return sighashFlags;
    }


    public static int calcSigHashValue(SigHashType mode, boolean anyoneCanPay, boolean useForkId) {
        Preconditions.checkArgument(SigHashType.ALL == mode || SigHashType.NONE == mode || SigHashType.SINGLE == mode); // enforce compatibility since this code was made before the SigHash enum was updated
        int sighashFlags = mode.value;
        if (anyoneCanPay)
            sighashFlags |= SigHashType.ANYONECANPAY.value;
        if(useForkId)
            sighashFlags |= SigHashType.FORKID.value;
        return sighashFlags;
    }


    /**
     * Returns a decoded signature.
     *
     * @param requireCanonicalEncoding if the encoding of the signature must
     * be canonical.
     * @throws RuntimeException if the signature is invalid or unparseable in some way.
     * @deprecated use {@link #decodeFromBitcoin(byte[], boolean, boolean)} instead.
     */
    @Deprecated
    public static TransactionSignature decodeFromBitcoin(byte[] bytes, boolean requireCanonicalEncoding) throws VerificationException, SignatureDecodeException {
        return decodeFromBitcoin(bytes, requireCanonicalEncoding, false);
    }


    /**
     * Returns a decoded signature.
     *
     * @param requireCanonicalEncoding if the encoding of the signature must
     * be canonical.
     * @param requireCanonicalSValue if the S-value must be canonical (below half
     * the order of the curve).
     * @throws SignatureDecodeException if the signature is unparseable in some way.
     * @throws VerificationException if the signature is invalid.
     */
    public static TransactionSignature decodeFromBitcoin(byte[] bytes, boolean requireCanonicalEncoding, boolean requireCanonicalSValue) throws SignatureDecodeException, VerificationException {
        // Bitcoin encoding is DER signature + sighash byte.
        if (requireCanonicalEncoding && !isEncodingCanonical(bytes))
            throw new VerificationException("Signature encoding is not canonical.");
        ECKey.ECDSASignature sig = ECKey.ECDSASignature.decodeFromDER(bytes);

        if (requireCanonicalSValue && !sig.isCanonical())
            throw new VerificationException("S-value is not canonical.");

        // In Bitcoin, any value of the final byte is valid, but not necessarily canonical. See javadocs for
        // isEncodingCanonical to learn more about this. So we must store the exact byte found.
        return new TransactionSignature(sig.r, sig.s, bytes[bytes.length - 1]);

    }


    /**
     * Returns true if the given signature is has canonical encoding, and will thus be accepted as standard by
     * Bitcoin Core. DER and the SIGHASH encoding allow for quite some flexibility in how the same structures
     * are encoded, and this can open up novel attacks in which a man in the middle takes a transaction and then
     * changes its signature such that the transaction hash is different but it's still valid. This can confuse wallets
     * and generally violates people's mental model of how Bitcoin should work, thus, non-canonical signatures are now
     * not relayed by default.
     */
    public static boolean isEncodingCanonical(byte[] signature) {
        // See Bitcoin Core's IsCanonicalSignature, https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
        // A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
        // Where R and S are not negative (their first byte has its highest bit not set), and not
        // excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
        // in which case a single 0 byte is necessary and even required).

        // Empty signatures, while not strictly DER encoded, are allowed.
        if (signature.length == 0)
            return true;

        if (signature.length < 9 || signature.length > 73)
            return false;

        int hashType = (signature[signature.length-1] & 0xff) & ~SigHashType.ANYONECANPAY.value; // mask the byte to prevent sign-extension hurting us
        if (hashType < SigHashType.ALL.value || hashType > SigHashType.SINGLE.value)
            return false;

        //                   "wrong type"                  "wrong length marker"
        if ((signature[0] & 0xff) != 0x30 || (signature[1] & 0xff) != signature.length-3)
            return false;

        int lenR = signature[3] & 0xff;
        if (5 + lenR >= signature.length || lenR == 0)
            return false;
        int lenS = signature[5+lenR] & 0xff;
        if (lenR + lenS + 7 != signature.length || lenS == 0)
            return false;

        //    R value type mismatch          R value negative
        if (signature[4-2] != 0x02 || (signature[4] & 0x80) == 0x80)
            return false;
        if (lenR > 1 && signature[4] == 0x00 && (signature[4+1] & 0x80) != 0x80)
            return false; // R value excessively padded

        //       S value type mismatch                    S value negative
        if (signature[6 + lenR - 2] != 0x02 || (signature[6 + lenR] & 0x80) == 0x80)
            return false;
        if (lenS > 1 && signature[6 + lenR] == 0x00 && (signature[6 + lenR + 1] & 0x80) != 0x80)
            return false; // S value excessively padded

        return true;
    }

    public byte[] getSignatureBytes() {
        return encodeToDER();
    }

    public static boolean hasForkId (byte[] signature)
    {

        if (signature.length == 0){
            return false;
        }

        int forkId = (signature[signature.length-1] & 0xff) & SigHashType.FORKID.value; // mask the byte to prevent sign-extension hurting us

        return forkId == SigHashType.FORKID.value;
    }

    public boolean anyoneCanPay() {
        return (sighashFlags & SigHashType.ANYONECANPAY.value) != 0;
    }
    public boolean useForkId() {
        return (sighashFlags & SigHashType.FORKID.value) != 0;
    }

    public SigHashType sigHashMode() {
        final int mode = sighashFlags & 0x1f;
        if (mode == SigHashType.NONE.value)
            return SigHashType.NONE;
        else if (mode == SigHashType.SINGLE.value)
            return SigHashType.SINGLE;
        else
            return SigHashType.ALL;
    }

    /**
     * What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
     * of the type used by Bitcoin we have to encode them using DER encoding, which is just a way to pack the two
     * components into a structure, and then we append a byte to the end for the sighash flags.
     */
    public byte[] encodeToBitcoin() {
        try {
            ByteArrayOutputStream bos = derByteStream();
            bos.write(sighashFlags);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    @Override
    public ECKey.ECDSASignature toCanonicalised() {
        return new TransactionSignature(super.toCanonicalised(), sigHashMode(), anyoneCanPay(), useForkId());
    }



    public byte[] toTxFormat() throws IOException {
        //return HEX encoded transaction Format

        WriteUtils wu = new WriteUtils();

        byte[] sigBytes = encodeToDER();

        wu.writeBytes(sigBytes, sigBytes.length);

        wu.writeUint8LE(sighashFlags);

        return wu.getBytes();
    }
}
