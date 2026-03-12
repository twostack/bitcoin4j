package org.twostack.bitcoin4j.script;

import java.util.List;

/**
 * Script info for OP_RETURN data output scripts.
 */
public class OpReturnScriptInfo extends ScriptInfo {

    private final List<byte[]> dataChunks;

    public OpReturnScriptInfo(List<byte[]> dataChunks) {
        super("OP_RETURN");
        this.dataChunks = dataChunks;
    }

    public List<byte[]> getDataChunks() {
        return dataChunks;
    }
}
