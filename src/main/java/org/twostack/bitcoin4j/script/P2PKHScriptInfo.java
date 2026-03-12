package org.twostack.bitcoin4j.script;

/**
 * Script info for Pay-to-Public-Key-Hash scripts.
 */
public class P2PKHScriptInfo extends ScriptInfo {

    private final byte[] pubKeyHash;

    public P2PKHScriptInfo(byte[] pubKeyHash) {
        super("P2PKH");
        this.pubKeyHash = pubKeyHash;
    }

    public byte[] getPubKeyHash() {
        return pubKeyHash;
    }
}
