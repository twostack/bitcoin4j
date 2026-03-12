package org.twostack.bitcoin4j;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import org.junit.Test;
import org.twostack.bitcoin4j.address.LegacyAddress;
import org.twostack.bitcoin4j.exception.AddressFormatException;
import org.twostack.bitcoin4j.exception.InvalidKeyException;
import org.twostack.bitcoin4j.params.NetworkAddressType;
import org.twostack.bitcoin4j.params.NetworkType;

import java.io.IOException;
import java.io.InputStreamReader;

import static org.junit.Assert.*;

public class Base58KeysTest {

    @Test
    public void validPrivateKeysFromBitcoindVectors() throws IOException {
        JsonNode json = new ObjectMapper()
                .readTree(new InputStreamReader(getClass().getResourceAsStream("base58_keys_valid.json"), Charsets.UTF_8));

        int tested = 0;
        for (JsonNode vector : json) {
            JsonNode metadata = vector.get(2);
            if (!metadata.get("isPrivkey").asBoolean()) continue;

            String wifKey = vector.get(0).asText();
            boolean isTestnet = metadata.get("isTestnet").asBoolean();
            boolean isCompressed = metadata.get("isCompressed").asBoolean();
            NetworkType expectedNetwork = isTestnet ? NetworkType.TEST : NetworkType.MAIN;

            try {
                PrivateKey key = PrivateKey.fromWIF(wifKey);
                assertEquals("Network mismatch for WIF: " + wifKey, expectedNetwork, key._networkType);
                assertEquals("Compression mismatch for WIF: " + wifKey, isCompressed, key._hasCompressedPubKey);
                tested++;
            } catch (InvalidKeyException e) {
                fail("Should not throw for valid WIF key: " + wifKey + " - " + e.getMessage());
            }
        }
        assertTrue("Should have tested at least one private key vector", tested > 0);
        System.out.println("Tested " + tested + " valid private key vectors");
    }

    @Test
    public void validAddressesFromBitcoindVectors() throws IOException {
        JsonNode json = new ObjectMapper()
                .readTree(new InputStreamReader(getClass().getResourceAsStream("base58_keys_valid.json"), Charsets.UTF_8));

        int tested = 0;
        for (JsonNode vector : json) {
            JsonNode metadata = vector.get(2);
            if (metadata.get("isPrivkey").asBoolean()) continue;

            String base58Address = vector.get(0).asText();
            String expectedHash = vector.get(1).asText();
            boolean isTestnet = metadata.get("isTestnet").asBoolean();

            try {
                LegacyAddress address = LegacyAddress.fromBase58(null, base58Address);

                // Verify the pubkey hash matches
                assertEquals("Hash mismatch for address: " + base58Address,
                        expectedHash, Utils.HEX.encode(address.getHash()));

                // Verify network detection
                NetworkAddressType nat = LegacyAddress.getNetworkFromAddress(base58Address);
                if (metadata.has("addrType")) {
                    String addrType = metadata.get("addrType").asText();
                    if ("pubkey".equals(addrType)) {
                        if (isTestnet) {
                            assertEquals(NetworkAddressType.TEST_PKH, nat);
                        } else {
                            assertEquals(NetworkAddressType.MAIN_PKH, nat);
                        }
                    } else if ("script".equals(addrType)) {
                        if (isTestnet) {
                            assertEquals(NetworkAddressType.TEST_P2SH, nat);
                        } else {
                            assertEquals(NetworkAddressType.MAIN_P2SH, nat);
                        }
                    }
                }
                tested++;
            } catch (AddressFormatException e) {
                fail("Should not throw for valid address: " + base58Address + " - " + e.getMessage());
            }
        }
        assertTrue("Should have tested at least one address vector", tested > 0);
        System.out.println("Tested " + tested + " valid address vectors");
    }

    @Test
    public void invalidKeysFromBitcoindVectors() throws IOException {
        JsonNode json = new ObjectMapper()
                .readTree(new InputStreamReader(getClass().getResourceAsStream("base58_keys_invalid.json"), Charsets.UTF_8));

        int tested = 0;
        for (JsonNode vector : json) {
            String invalidKey = vector.get(0).asText();

            // Should fail as address
            boolean addressFailed = false;
            try {
                LegacyAddress.fromBase58(null, invalidKey);
            } catch (Exception e) {
                addressFailed = true;
            }

            // Should fail as private key
            boolean keyFailed = false;
            try {
                PrivateKey.fromWIF(invalidKey);
            } catch (Exception e) {
                keyFailed = true;
            }

            assertTrue("Invalid key should fail as both address and WIF: " + invalidKey,
                    addressFailed || keyFailed);
            tested++;
        }
        assertTrue("Should have tested at least one invalid key vector", tested > 0);
        System.out.println("Tested " + tested + " invalid key vectors");
    }
}
