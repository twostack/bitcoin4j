package org.twostack.bitcoin4j.script;

import java.util.List;

/**
 * Script info for Pay-to-Multisig scripts.
 */
public class P2MSScriptInfo extends ScriptInfo {

    private final int threshold;
    private final int totalKeys;
    private final List<byte[]> publicKeys;

    public P2MSScriptInfo(int threshold, int totalKeys, List<byte[]> publicKeys) {
        super("P2MS");
        this.threshold = threshold;
        this.totalKeys = totalKeys;
        this.publicKeys = publicKeys;
    }

    public int getThreshold() {
        return threshold;
    }

    public int getTotalKeys() {
        return totalKeys;
    }

    public List<byte[]> getPublicKeys() {
        return publicKeys;
    }
}
