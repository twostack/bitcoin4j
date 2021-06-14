/*
 * Copyright by the original author or authors.
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

import org.junit.Test;
import org.twostack.bitcoin4j.Utils;

import java.io.IOException;

import static org.junit.Assert.assertArrayEquals;

public class TransactionInputTest {

    final static CharSequence txInputHex = "5884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a40000000000ffffffff";

    @Test
    public void canSerializeInput() throws IOException {

        byte[] inputBytes = Utils.HEX.decode(txInputHex);
        TransactionInput txInput = TransactionInput.fromByteArray(inputBytes);

        byte[] serializedBytes = txInput.serialize();

        assertArrayEquals(inputBytes, serializedBytes);
    }

    @Test
    public void canDeserializeInput(){

    }
}
