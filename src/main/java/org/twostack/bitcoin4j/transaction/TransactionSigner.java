
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

import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PrivateKey;
import org.twostack.bitcoin4j.Sha256Hash;
import org.twostack.bitcoin4j.exception.SigHashException;
import org.twostack.bitcoin4j.exception.SignatureDecodeException;
import org.twostack.bitcoin4j.exception.TransactionException;
import org.twostack.bitcoin4j.script.Script;

import java.io.IOException;


public class TransactionSigner {

    private byte[] hash;
    private byte[] preImage;
    private Transaction signedTransaction;
    private int sigHashType;
    private TransactionSignature signature;
    private PrivateKey signingKey;


    public byte[] getHash() {
        return hash;
    }

    public Transaction getSignedTransaction() {
        return signedTransaction;
    }

    public int getSigHashType() {
        return sigHashType;
    }

    public TransactionSignature getSignature() {
        return signature;
    }

    public byte[] getPreImage() {
        return preImage;
    }

    /** Constructs a new instance of the TransactionSigner.
     * NOTE: The SigHashType for signing will default to a value of
     *       (SigHashType.ALL.value | SigHashType.FORKID.value)
     */
//     TransactionSigner(){
//        this.sigHashType = SigHashType.ALL.value | SigHashType.FORKID.value;
//    }

    /** Constructs a new instance of the TransactionSigner.
     * NOTE: The SigHashType for signing will default to a value of
     *       (SigHashType.ALL.value | SigHashType.FORKID.value)
     *
     * @param sigHashType - Flags that govern which SigHash algorithm to use during signature generation
     */
    public TransactionSigner(int sigHashType, PrivateKey signingKey){
        this.sigHashType = sigHashType;
        this.signingKey = signingKey;
    }

    /** Signs the provided transaction, and populates the corresponding input's
     *  LockingScriptBuilder with the signature. Responsibility for what to
     *  do with the Signature (populate appropriate template) is left to the
     *  LockingScriptBuilder instance.
     *
     *  NOTE: This invocation will use the SigHashType set as part of the
     *  constructor invocation. If the default constructor is invoked then
     *  the SigHashType defaults to (SigHashType.ALL.value | SigHashType.FORKID.value) :
     *
     *
     * @param unsignedTxn  - Unsigned Transaction
     * @param utxo - Funding transaction's Output to sign over
     * @param inputIndex - Input of the current Transaction we are signing for
     * @return Signed Transaction
     * @throws TransactionException
     * @throws IOException
     * @throws SigHashException
     * @throws SignatureDecodeException
     */
    public Transaction sign(
            Transaction unsignedTxn,
            TransactionOutput utxo,
            int inputIndex) throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        return this.sign(unsignedTxn, utxo, inputIndex, signingKey, sigHashType);
    }

    /** Signs the provided transaction, and populates the corresponding input's
     *  LockingScriptBuilder with the signature. Responsibility for what to
     *  do with the Signature (populate appropriate template) is left to the
     *  LockingScriptBuilder instance
     *
     *
     * @param unsignedTxn  - Unsigned Transaction
     * @param utxo - Funding transaction's Output to sign over
     * @param inputIndex - Input of the current Transaction we are signing for
     * @param signingKey - Private key to sign with
     * @param sigHashType - Flags that govern which SigHash algorithm is applied
     * @return Signed Transaction
     * @throws TransactionException
     * @throws IOException
     * @throws SigHashException
     * @throws SignatureDecodeException
     */
    public Transaction sign(
            Transaction unsignedTxn,
            TransactionOutput utxo,
            int inputIndex,
            PrivateKey signingKey,
            int sigHashType) throws TransactionException, IOException, SigHashException, SignatureDecodeException {

        //FIXME: This is a test work-around for why I can't sign an unsigned raw txn


        //FIXME: This should account for ANYONECANPAY mask that limits outputs to sign over
        ///      NOTE: Stripping Subscript should be done inside SIGHASH class
        Script subscript = utxo.getScript();
        SigHash sigHash = new SigHash();

        //NOTE: Return hash in LittleEndian (already double-sha256 applied)
        preImage = sigHash.getSighashPreimage(unsignedTxn, sigHashType, inputIndex, subscript, utxo.getAmount());

        TransactionSignature sig = signPreimage(signingKey, preImage, sigHashType);

        TransactionInput input = unsignedTxn.getInputs().get(inputIndex);
        UnlockingScriptBuilder scriptBuilder = input.getUnlockingScriptBuilder();

        if (scriptBuilder != null) {
            scriptBuilder.addSignature(sig);
        }else{
            throw new TransactionException("Trying to sign a Transaction Input that is missing a SignedUnlockBuilder");
        }

        this.hash = hash;
        this.signedTransaction = unsignedTxn;
        this.sigHashType = sigHashType;
        this.signature = sig;

        return unsignedTxn; //signature has been added
    }

    public TransactionSignature signPreimage(PrivateKey signingKey, byte[] preImage, int sigHashType) throws SignatureDecodeException {

        byte[] hash = Sha256Hash.hashTwice(preImage);

        //FIXME: This kind of required round-tripping into the base class of TransactionSignature smells funny
        //       We should have a cleaner constructor for TransactionSignature
        byte[] signedBytes =  signingKey.sign(hash);
        ECKey.ECDSASignature ecSig = ECKey.ECDSASignature.decodeFromDER(signedBytes);
        return new TransactionSignature(ecSig.r, ecSig.s, sigHashType);
    }

    public PrivateKey getSigningKey() {
        return signingKey;
    }

    public void setSigningKey (PrivateKey privateKey) {
        this.signingKey = privateKey;
    }


/** sf:> This seems like more Core buggery to me. What sort of TX remains valid without proper SighashType ???
     *
     * This is required for signatures which use a sigHashType which cannot be represented using SigHash and anyoneCanPay
     * See transaction c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73, which has sigHashType 0
     */
//    public Sha256Hash hashForSignature(Transaction txn, int inputIndex, byte[] connectedScript, byte sigHashType) {
//
//    }

}
