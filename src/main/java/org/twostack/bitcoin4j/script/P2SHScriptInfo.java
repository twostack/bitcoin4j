package org.twostack.bitcoin4j.script;

/**
 * Script info for Pay-to-Script-Hash scripts.
 */
public class P2SHScriptInfo extends ScriptInfo {

    private final byte[] scriptHash;

    public P2SHScriptInfo(byte[] scriptHash) {
        super("P2SH");
        this.scriptHash = scriptHash;
    }

    public byte[] getScriptHash() {
        return scriptHash;
    }
}
