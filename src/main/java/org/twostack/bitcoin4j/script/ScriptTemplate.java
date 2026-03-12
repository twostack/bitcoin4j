package org.twostack.bitcoin4j.script;

import org.twostack.bitcoin4j.PublicKey;

import java.util.List;

/**
 * Interface for script template pattern matching and info extraction.
 */
public interface ScriptTemplate {

    /**
     * Returns the name of this template (e.g. "P2PKH", "P2PK").
     */
    String getName();

    /**
     * Returns true if the given script matches this template's pattern.
     */
    boolean matches(Script script);

    /**
     * Returns true if the script can be satisfied (spent) by the given set of keys.
     */
    boolean canBeSatisfiedBy(List<PublicKey> keys, Script script);

    /**
     * Extracts typed information from a script matching this template.
     *
     * @throws ScriptException if the script does not match this template
     */
    ScriptInfo extractScriptInfo(Script script);
}
