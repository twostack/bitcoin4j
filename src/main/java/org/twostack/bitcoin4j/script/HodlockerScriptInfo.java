package org.twostack.bitcoin4j.script;

import java.math.BigInteger;

/**
 * Script info for HODLocker timelock scripts.
 */
public class HodlockerScriptInfo extends ScriptInfo {

    private final byte[] pubKeyHash;
    private final BigInteger lockHeight;

    public HodlockerScriptInfo(byte[] pubKeyHash, BigInteger lockHeight) {
        super("HODLocker");
        this.pubKeyHash = pubKeyHash;
        this.lockHeight = lockHeight;
    }

    public byte[] getPubKeyHash() {
        return pubKeyHash;
    }

    public BigInteger getLockHeight() {
        return lockHeight;
    }
}
