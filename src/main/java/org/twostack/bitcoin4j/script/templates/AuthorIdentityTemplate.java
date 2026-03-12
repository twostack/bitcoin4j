package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

/**
 * Template for Author Identity protocol scripts.
 * Pattern: OP_FALSE OP_RETURN <AuthorIdentity prefix> <algorithm> <address> <signature> [<field indices...>]
 *
 * The prefix is the Bitcoin address: "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva"
 */
public class AuthorIdentityTemplate implements ScriptTemplate {

    public static final String AUTHOR_IDENTITY_PREFIX = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";

    @Override
    public String getName() {
        return "AuthorIdentity";
    }

    @Override
    public boolean matches(Script script) {
        List<ScriptChunk> chunks = script.getChunks();
        if (chunks.size() < 6) return false;

        // OP_FALSE OP_RETURN
        if (!chunks.get(0).equalsOpCode(OP_FALSE)) return false;
        if (!chunks.get(1).equalsOpCode(OP_RETURN)) return false;

        // Check prefix
        byte[] prefixData = chunks.get(2).data;
        if (prefixData == null) return false;

        String prefix = new String(prefixData, StandardCharsets.UTF_8);
        return AUTHOR_IDENTITY_PREFIX.equals(prefix);
    }

    @Override
    public boolean canBeSatisfiedBy(List<PublicKey> keys, Script script) {
        // Data protocol, not spendable
        return false;
    }

    @Override
    public ScriptInfo extractScriptInfo(Script script) {
        if (!matches(script)) {
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Script is not an AuthorIdentity script");
        }

        List<ScriptChunk> chunks = script.getChunks();

        String signingAlgorithm = extractString(chunks, 3);
        String publicKey = extractString(chunks, 4);
        String signature = extractString(chunks, 5);

        return new AuthorIdentityScriptInfo(signingAlgorithm, publicKey, signature);
    }

    private String extractString(List<ScriptChunk> chunks, int index) {
        if (index >= chunks.size() || chunks.get(index).data == null) {
            return null;
        }
        return new String(chunks.get(index).data, StandardCharsets.UTF_8);
    }
}
