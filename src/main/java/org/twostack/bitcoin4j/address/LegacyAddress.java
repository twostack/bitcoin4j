/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Giannis Dzegoutanis
 * Copyright 2015 Andreas Schildbach
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

package org.twostack.bitcoin4j.address;

import com.google.common.primitives.UnsignedBytes;
import org.twostack.bitcoin4j.Address;
import org.twostack.bitcoin4j.ECKey;
import org.twostack.bitcoin4j.PublicKey;
import org.twostack.bitcoin4j.exception.AddressFormatException;
import org.twostack.bitcoin4j.params.AddressType;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.params.NetworkParameters;
import org.twostack.bitcoin4j.params.NetworkType;
import org.twostack.bitcoin4j.script.Script.ScriptType;

import javax.annotation.Nullable;
import java.util.Arrays;
import java.util.Objects;

/**
 * <p>A Bitcoin address looks like 1MsScoe2fTJoq4ZPdQgqyhgWeoNamYPevy and is derived from an elliptic curve public key
 * plus a set of network parameters.
 *
 * <p>A standard address is built by taking the RIPE-MD160 hash of the public key bytes, with a version prefix and a
 * checksum suffix, then encoding it textually as base58. The version prefix is used to both denote the network for
 * which the address is valid (see {@link NetworkParameters}, and also to indicate how the bytes inside the address
 * should be interpreted. Whilst almost all addresses today are hashes of public keys, another (currently unsupported
 * type) can contain a hash of a script instead.</p>
 */
public class LegacyAddress extends Address {
    /**
     * An address is a RIPEMD160 hash of a public key, therefore is always 160 bits or 20 bytes.
     */
    public static final int LENGTH = 20;

    /** True if P2SH, false if P2PKH. */
    public final boolean p2sh;


    /**
     * Private constructor. Use {@link #fromBase58(NetworkType, String)},
     * {@link #fromPubKeyHash(NetworkAddressType, byte[])}, {@link #fromScriptHash(NetworkType, byte[])} or
     * {@link #fromKey(NetworkAddressType, PublicKey)}.
     *
     * @param addressType
     *            network this address is valid for
     * @param p2sh
     *            true if hash160 is hash of a script, false if it is hash of a pubkey
     * @param hash160
     *            20-byte hash of pubkey or script
     */
    private LegacyAddress(NetworkAddressType addressType, boolean p2sh, byte[] hash160) throws AddressFormatException {
        super(addressType, hash160);
        if (hash160.length != 20)
            throw new AddressFormatException.InvalidDataLength(
                    "Legacy addresses are 20 byte (160 bit) hashes, but got: " + hash160.length);
        this.p2sh = p2sh;
    }

    /**
     * Construct a {@link LegacyAddress} that represents the given pubkey hash. The resulting address will be a P2PKH type of
     * address.
     * 
     * @param networkAddressType
     *            network this address is valid for
     * @param hash160
     *            20-byte pubkey hash
     * @return constructed address
     */
    public static LegacyAddress fromPubKeyHash(NetworkAddressType networkAddressType, byte[] hash160) throws AddressFormatException {
        return new LegacyAddress(networkAddressType, false, hash160);
    }

    /**
     * Construct a {@link LegacyAddress} that represents the public part of the given {@link ECKey}. Note that an address is
     * derived from a hash of the public key and is not the public key itself.
     * 
     * @param networkAddressType
     *            network this address is valid for
     * @param key
     *            only the public part is used
     * @return constructed address
     */
    public static LegacyAddress fromKey(NetworkAddressType networkAddressType, PublicKey key) {
        return fromPubKeyHash(networkAddressType, key.getPubKeyHash());
    }

    /**
     * Construct a {@link LegacyAddress} that represents the given P2SH script hash.
     * 
     * @param networkType
     *            network this address is valid for
     * @param hash160
     *            P2SH script hash
     * @return constructed address
     */
    public static LegacyAddress fromScriptHash(NetworkType networkType, byte[] hash160) throws AddressFormatException {

        if (networkType == NetworkType.MAIN){
            return new LegacyAddress(NetworkAddressType.MAIN_P2SH, true, hash160);
        }else{
            return new LegacyAddress(NetworkAddressType.TEST_P2SH, true, hash160);
        }

    }

    /**
     * Construct a {@link LegacyAddress} from its base58 form.
     * 
     * @param networkType
     *            expected network this address is valid for, or null if if the network should be derived from the
     *            base58
     * @param base58
     *            base58-encoded textual form of the address
     * @throws AddressFormatException
     *             if the given base58 doesn't parse or the checksum is invalid
     * @throws AddressFormatException.WrongNetwork
     *             if the given address is valid but for a different chain (eg testnet vs mainnet)
     */
    public static LegacyAddress fromBase58(@Nullable NetworkType networkType, String base58)
            throws AddressFormatException {
        byte[] versionAndDataBytes = Base58.decodeChecked(base58);
        int version = versionAndDataBytes[0] & 0xFF;
        byte[] bytes = Arrays.copyOfRange(versionAndDataBytes, 1, versionAndDataBytes.length);

        if (networkType == null) {
            NetworkAddressType derivedType = NetworkParameters.getNetworkAddressType(version);
            return new LegacyAddress(derivedType, false, bytes);
        } else {

            AddressType versionType = NetworkParameters.getAddressType(version);
            NetworkAddressType versionAddressType = NetworkParameters.getNetworkAddressType(version);

            if (! NetworkParameters.getNetworkTypes(version).contains(networkType))
                throw new AddressFormatException.WrongNetwork(version);

            if (versionType == AddressType.PUBKEY_HASH){
                return new LegacyAddress(versionAddressType, false, bytes);
            }else if(versionType == AddressType.SCRIPT_HASH){
                return new LegacyAddress(versionAddressType, true, bytes);
            }

            throw new AddressFormatException.WrongNetwork(version);
        }

    }

    /**
     * Get the version header of an address. This is the first byte of a base58 encoded address.
     * 
     * @return version header as one byte
     */
    public int getVersion() {
        return NetworkParameters.getNetworkVersion(networkAddressType);
    }

    /**
     * Returns the base58-encoded textual form, including version and checksum bytes.
     * 
     * @return textual form
     */
    public String toBase58() {
        return Base58.encodeChecked(getVersion(), bytes);
    }

    /** The (big endian) 20 byte hash that is the core of a Bitcoin address. */
    @Override
    public byte[] getHash() {
        return bytes;
    }

    /**
     * Get the type of output script that will be used for sending to the address. This is either
     * {@link ScriptType#P2PKH} or {@link ScriptType#P2SH}.
     * 
     * @return type of output script
     */
    @Override
    public ScriptType getOutputScriptType() {
        if (networkAddressType == NetworkAddressType.MAIN_P2SH || networkAddressType == NetworkAddressType.TEST_P2SH){
            return ScriptType.P2SH;
        }else{
            return ScriptType.P2PKH;
        }
    }


    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet.
     *
     * @return network the address is valid for
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     */
    public static NetworkAddressType getNetworkFromAddress(String address) throws AddressFormatException {
        return LegacyAddress.fromBase58(null, address).networkAddressType;
    }

    /**
     * Given an address, examines the version byte and attempts to find a matching NetworkParameters. If you aren't sure
     * which network the address is intended for (eg, it was provided by a user), you can use this to decide if it is
     * compatible with the current wallet.
     * 
     * @return network the address is valid for
     * @throws AddressFormatException if the given base58 doesn't parse or the checksum is invalid
     */
//    public static NetworkParameters getParametersFromAddress(String address) throws AddressFormatException {
//        return LegacyAddress.fromBase58(null, address).getParameters();
//    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        LegacyAddress other = (LegacyAddress) o;
        return super.equals(other) && this.networkAddressType == other.networkAddressType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), networkAddressType);
    }

    @Override
    public String toString() {
        return toBase58();
    }

    @Override
    public LegacyAddress clone() throws CloneNotSupportedException {
        return (LegacyAddress) super.clone();
    }

    /**
     * {@inheritDoc}
     *
     * @param o other {@code Address} object
     * @return comparison result
     */
    @Override
    public int compareTo(Address o) {
        int result = compareAddressPartial(o);
        if (result != 0) return result;

        // Compare version byte and finally the {@code bytes} field itself
        result = Integer.compare(getVersion(), ((LegacyAddress) o).getVersion());
        return result != 0 ? result : UnsignedBytes.lexicographicalComparator().compare(this.bytes, o.bytes);
    }
}
