/*
 * Copyright 2021 Stephan M. February
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.twostack.bitcoin4j.script;

import java.util.LinkedList;

/**
 * Callback interface for step-by-step script execution tracing.
 * Implement this interface to receive detailed information about each
 * opcode executed during script evaluation.
 */
public interface ScriptTraceCallback {

    /**
     * Called after each opcode is executed during script evaluation.
     *
     * @param programCounter the index of the opcode in the script's chunk list
     * @param opcode         the opcode that was just executed
     * @param opcodeName     human-readable name of the opcode (e.g. "OP_DUP")
     * @param stack          the current main stack state (read-only view recommended)
     * @param altStack       the current alt-stack state (read-only view recommended)
     */
    void onStep(int programCounter, int opcode, String opcodeName,
                LinkedList<byte[]> stack, LinkedList<byte[]> altStack);
}
