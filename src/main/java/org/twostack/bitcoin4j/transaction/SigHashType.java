
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
package org.twostack.bitcoin4j.transaction;

public enum SigHashType {
    ALL(1),
    NONE(2),
    SINGLE(3),
    FORKID (0x40),
    ANYONECANPAY(0x80), // Caution: Using this type in isolation is non-standard. Treated similar to ANYONECANPAY_ALL.
    ANYONECANPAY_ALL(0x81),
    ANYONECANPAY_NONE(0x82),
    ANYONECANPAY_SINGLE(0x83),
    UNSET(0); // Caution: Using this type in isolation is non-standard. Treated similar to ALL.

    public final int value;

    /**
     * @param value
     */
    private SigHashType(final int value) {
        this.value = value;
    }

    /**
     * @return the value as a byte
     */
    public byte byteValue() {
        return (byte) this.value;
    }

    public static boolean hasValue(int value){

        for (SigHashType t : values()){
            if (t.value == value)
                return true;
        }

        return false;
    }
}
