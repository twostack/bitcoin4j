package org.twostack.bitcoin4j.transaction;

import org.twostack.bitcoin4j.script.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class UnspendableDataLockBuilder extends LockingScriptBuilder{

    List<ByteBuffer> dataList = new ArrayList<ByteBuffer>();


    public UnspendableDataLockBuilder(List<ByteBuffer> buffers){
        this.dataList = buffers;
    }

    public UnspendableDataLockBuilder(Script script){
        parse(script);
    }

    /**
     * Deserialize an OP_RETURN data output
     *
     * The OP_RETURN data output is to have the format:
     *
     * OP_FALSE OP_RETURN [data 1] [data 2] ... [data n]
     *
     */
    private void parse(Script script){

        if (script != null && script.getProgram().length != 0){

            List<ScriptChunk> chunks = script.getChunks();
            if (chunks.get(0).opcode == ScriptOpCodes.OP_FALSE
                && chunks.get(1).opcode == ScriptOpCodes.OP_RETURN){

                for (int i = 2; i < chunks.size(); i++){
                    if (chunks.get(i).opcode > ScriptOpCodes.OP_PUSHDATA4) {
                        throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                                "Only data pushes are allowed here. Consider making a custom LockingScriptBuilder.");
                    }

                    dataList.add(ByteBuffer.wrap(chunks.get(i).data));
                }
            }


        }else{
            throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR,
                    "Invalid Script or malformed Data in Script");
        }
    }

    @Override
    public Script getLockingScript() {

        ScriptBuilder builder = new ScriptBuilder();

        builder.op(ScriptOpCodes.OP_FALSE);
        builder.op(ScriptOpCodes.OP_RETURN);

        for (ByteBuffer buffer: dataList) {
            builder.data(buffer.array());
        }

        return builder.build();

    }


}
