package org.twostack.bitcoin4j.utils;

import org.twostack.bitcoin4j.UnsafeByteArrayOutputStream;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.script.Script;
import org.twostack.bitcoin4j.script.ScriptOpCodes;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Set;

import static org.twostack.bitcoin4j.Utils.HEX;
import static org.twostack.bitcoin4j.script.ScriptOpCodes.OP_INVALIDOPCODE;

public class TestUtil {


    public static Script parseScriptString(String string) throws IOException {
        String[] words = string.split("[ \\t\\n]");

        UnsafeByteArrayOutputStream out = new UnsafeByteArrayOutputStream();

        for(String w : words) {
            if (w.equals(""))
                continue;
            if (w.matches("^-?[0-9]*$")) {
                // Number
                long val = Long.parseLong(w);
                if (val >= -1 && val <= 16)
                    out.write(Script.encodeToOpN((int)val));
                else
                    Script.writeBytes(out, Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(val), false)));
            } else if (w.matches("^0x[0-9a-fA-F]*$")) {
                // Raw hex data, inserted NOT pushed onto stack:
                out.write(HEX.decode(w.substring(2).toLowerCase()));
            } else if (w.length() >= 2 && w.startsWith("'") && w.endsWith("'")) {
                // Single-quoted string, pushed as data. NOTE: this is poor-man's
                // parsing, spaces/tabs/newlines in single-quoted strings won't work.
                Script.writeBytes(out, w.substring(1, w.length() - 1).getBytes(StandardCharsets.UTF_8));
            } else if (ScriptOpCodes.getOpCode(w) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w));
            } else if (w.startsWith("OP_") && ScriptOpCodes.getOpCode(w.substring(3)) != OP_INVALIDOPCODE) {
                // opcode, e.g. OP_ADD or OP_1:
                out.write(ScriptOpCodes.getOpCode(w.substring(3)));
            } else {
                throw new RuntimeException("Invalid word: '" + w + "'");
            }
        }

        return new Script(out.toByteArray());
    }


    public static Set<Script.VerifyFlag> parseVerifyFlags(String str) {
        Set<Script.VerifyFlag> flags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (!"NONE".equals(str)) {
            for (String flag : str.split(",")) {
                try {
                    flags.add(Script.VerifyFlag.valueOf(flag));
                } catch (IllegalArgumentException x) {
                    System.out.println("Cannot handle verify flag {} -- ignored.");
                }
            }
        }
        return flags;
    }
}
