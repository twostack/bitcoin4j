package org.twostack.bitcoin.block;

import org.twostack.bitcoin.Sha256Hash;

public class Block {

    /** How many bytes are required to represent a block header WITHOUT the trailing 00 length byte. */
    public static final int HEADER_SIZE = 80;

    static final long ALLOWED_TIME_DRIFT = 2 * 60 * 60; // Same value as Bitcoin Core.

    /**
     * Legacy. Still applies to BTC. BSV has unbounded blocks
     *
     * A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to
     * upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to
     * avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
       public static final int MAX_BLOCK_SIZE = 1 * 1000 * 1000;
     */

    /** A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing. */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    /** Value to use if the block height is unknown */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /** Height of the first block */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long BLOCK_VERSION_GENESIS = 1;
    /** Block version introduced in BIP 34: Height in coinbase */
    public static final long BLOCK_VERSION_BIP34 = 2;
    /** Block version introduced in BIP 66: Strict DER signatures */
    public static final long BLOCK_VERSION_BIP66 = 3;
    /** Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY */
    public static final long BLOCK_VERSION_BIP65 = 4;

    // Fields defined as part of the protocol format.
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot;
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;
}
