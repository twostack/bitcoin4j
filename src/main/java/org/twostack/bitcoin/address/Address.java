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

package org.twostack.bitcoin.address;

import org.twostack.bitcoin.ECKey;
import org.twostack.bitcoin.exception.AddressFormatException;
import org.twostack.bitcoin.params.NetworkAddressType;
import org.twostack.bitcoin.script.Script;
import org.twostack.bitcoin.script.Script.ScriptType;

import javax.annotation.Nullable;

/**
 * <p>
 * Base class for addresses, e.g. legacy addresses ({@link org.twostack.bitcoin.address.LegacyAddress}).
 * </p>
 * 
 * <p>
 * Use {@link #fromString(NetworkAddressType, String)} to conveniently construct any kind of address from its textual
 * form.
 * </p>
 */
public abstract class Address extends PrefixedChecksummedBytes implements Comparable<Address> {
    public Address(NetworkAddressType networkAddressType, byte[] bytes) {
        super(networkAddressType, bytes);
    }

    /**
     * Construct an address from its textual form.
     * 
     * @param params
     *            the expected network this address is valid for, or null if the network should be derived from the
     *            textual form
     * @param str
     *            the textual form of the address, such as "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL" or
     *            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
     * @return constructed address
     * @throws AddressFormatException
     *             if the given string doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork
     *             if the given string is valid but not for the expected network (eg testnet vs mainnet)
     */
    public static Address fromString(@Nullable NetworkAddressType params, String str)
            throws AddressFormatException {
            return LegacyAddress.fromBase58(params, str);
    }

    /**
     * Construct an {@link Address} that represents the public part of the given {@link ECKey}.
     * 
     * @param params
     *            network this address is valid for
     * @param key
     *            only the public part is used
     * @param outputScriptType
     *            script type the address should use
     * @return constructed address
     */
//    public static Address fromKey(final NetworkAddressType params, final ECKey key, final ScriptType outputScriptType) {
//        if (outputScriptType == Script.ScriptType.P2PKH)
//            return LegacyAddress.fromKey(params, key);
//        else
//            throw new IllegalArgumentException(outputScriptType.toString());
//    }

    /**
     * Get either the public key hash or script hash that is encoded in the address.
     * 
     * @return hash that is encoded in the address
     */
    public abstract byte[] getHash();

    /**
     * Get the type of output script that will be used for sending to the address.
     * 
     * @return type of output script
     */
    public abstract ScriptType getOutputScriptType();

    /**
     * Comparison field order for addresses is:
     * <ol>
     *     <li>{@link NetworkAddressType #getId()}</li>
     *     <li>Legacy vs. Segwit</li>
     *     <li>(Legacy only) Version byte</li>
     *     <li>remaining {@code bytes}</li>
     * </ol>
     * <p>
     * Implementations may use {@code compareAddressPartial} for tests 1 and 2.
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    abstract public int compareTo(Address o);

    /**
     * FIXME: Is this needed in absence of Segwit ?
     *
     * Comparator for the first two comparison fields in {@code Address} comparisons, see {@link Address#compareTo(Address)}.
     * Used by {@link LegacyAddress#compareTo(Address)} and { SegwitAddress#compareTo(Address)}.
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    protected int compareAddressPartial(Address o) {
        // First compare netParams
        int result = this.networkAddressType.compareTo(o.networkAddressType);
        return result;
    }
}
