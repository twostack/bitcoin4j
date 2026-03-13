package org.twostack.bitcoin4j.script.templates;

import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.script.*;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.twostack.bitcoin4j.script.ScriptOpCodes.*;

/**
 * Template for B:// protocol data scripts.
 * Pattern: {@code OP_FALSE OP_RETURN <B prefix> <data> <mediaType> [<encoding>] [<filename>]}
 *
 * The prefix is the Bitcoin address: "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut"
 */
public class BProtocolTemplate implements ScriptTemplate {

    public static final String B_PROTOCOL_PREFIX = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";

    @Override
    public String getName() {
        return "BProtocol";
    }

    @Override
    public boolean matches(Script script) {
        List<ScriptChunk> chunks = script.getChunks();
        if (chunks.size() < 5) return false;

        // OP_FALSE OP_RETURN
        if (!chunks.get(0).equalsOpCode(OP_FALSE)) return false;
        if (!chunks.get(1).equalsOpCode(OP_RETURN)) return false;

        // Check prefix
        byte[] prefixData = chunks.get(2).data;
        if (prefixData == null) return false;

        String prefix = new String(prefixData, StandardCharsets.UTF_8);
        return B_PROTOCOL_PREFIX.equals(prefix);
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
                    "Script is not a B:// protocol script");
        }

        List<ScriptChunk> chunks = script.getChunks();

        // chunk 3: data (binary)
        byte[] data = chunks.get(3).data;

        // chunk 4: media type
        String mediaType = extractString(chunks, 4);

        // chunk 5: encoding (optional)
        String encoding = extractString(chunks, 5);

        // chunk 6: filename (optional)
        String filename = extractString(chunks, 6);

        return new BProtocolScriptInfo(data, mediaType, encoding, filename);
    }

    private String extractString(List<ScriptChunk> chunks, int index) {
        if (index >= chunks.size() || chunks.get(index).data == null) {
            return null;
        }
        return new String(chunks.get(index).data, StandardCharsets.UTF_8);
    }
}
