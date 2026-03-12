package org.twostack.bitcoin4j.script;

/**
 * Script info for Pay-to-Public-Key scripts.
 */
public class P2PKScriptInfo extends ScriptInfo {

    private final byte[] publicKey;

    public P2PKScriptInfo(byte[] publicKey) {
        super("P2PK");
        this.publicKey = publicKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }
}
