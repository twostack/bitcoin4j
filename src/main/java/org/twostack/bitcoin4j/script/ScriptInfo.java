package org.twostack.bitcoin4j.script;

/**
 * Base class for typed script information extracted from script templates.
 */
public abstract class ScriptInfo {

    private final String type;

    protected ScriptInfo(String type) {
        this.type = type;
    }

    /**
     * Returns the script type name (e.g. "P2PKH", "P2PK", "P2MS").
     */
    public String getType() {
        return type;
    }
}
