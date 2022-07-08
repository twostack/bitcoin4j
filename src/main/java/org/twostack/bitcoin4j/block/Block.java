package org.twostack.bitcoin4j.block;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import org.twostack.bitcoin4j.Sha256Hash;
import org.twostack.bitcoin4j.UnsafeByteArrayOutputStream;
import org.twostack.bitcoin4j.Utils;
import org.twostack.bitcoin4j.VarInt;
import org.twostack.bitcoin4j.exception.ProtocolException;
import org.twostack.bitcoin4j.transaction.ReadUtils;
import org.twostack.bitcoin4j.transaction.Transaction;

import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;

import static org.twostack.bitcoin4j.Sha256Hash.hashTwice;

/**
 * <p>A block is a group of transactions, and is one of the fundamental data structures of the Bitcoin system.
 * It records a set of {@link Transaction}s together with some data that links it into a place in the global block
 * chain, and proves that a difficult calculation was done over its contents. See
 * <a href="http://www.bitcoin.org/bitcoin.pdf">the Bitcoin technical paper</a> for
 * more detail on blocks.</p>
 *
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public class Block {

    // Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
    // MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
    // of the size of the ideal encoding in addition to the actual message size (which Message needs)
    protected int optimalEncodingMessageSize;

    /**
     * How many bytes are required to represent a block header WITHOUT the trailing 00 length byte.
     */
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

    /**
     * A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing.
     */
    public static final long EASIEST_DIFFICULTY_TARGET = 0x207fFFFFL;

    /**
     * Value to use if the block height is unknown
     */
    public static final int BLOCK_HEIGHT_UNKNOWN = -1;
    /**
     * Height of the first block
     */
    public static final int BLOCK_HEIGHT_GENESIS = 0;

    public static final long BLOCK_VERSION_GENESIS = 1;
    /**
     * Block version introduced in BIP 34: Height in coinbase
     */
    public static final long BLOCK_VERSION_BIP34 = 2;
    /**
     * Block version introduced in BIP 66: Strict DER signatures
     */
    public static final long BLOCK_VERSION_BIP66 = 3;
    /**
     * Block version introduced in BIP 65: OP_CHECKLOCKTIMEVERIFY
     */
    public static final long BLOCK_VERSION_BIP65 = 4;

    // Fields defined as part of the protocol format.
    private long version;
    private Sha256Hash prevBlockHash;
    private Sha256Hash merkleRoot;
    private long time;
    private long difficultyTarget; // "nBits"
    private long nonce;

    /**
     * Stores the hash of the block. If null, getHash() will recalculate it.
     */
    private Sha256Hash blockHash;

    protected boolean headerBytesValid;
    protected boolean transactionBytesValid;


    // The raw message payload bytes themselves.
    protected byte[] payload;

    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message payload.
    protected int cursor;

    List<Sha256Hash> txids;

    @VisibleForTesting
    List<Transaction> transactions;

    public Block(long version, Sha256Hash prevBlockHash, Sha256Hash merkleRoot, long time,
                 long difficultyTarget, long nonce, List<Transaction> transactions) {

        this.version = version;
        this.prevBlockHash = prevBlockHash;
        this.merkleRoot = merkleRoot;
        this.time = time;
        this.difficultyTarget = difficultyTarget;
        this.nonce = nonce;
        this.transactions = new LinkedList<>();
        this.transactions.addAll(transactions);
    }

    public Block(byte[] payload) throws IOException {
        parse(payload);
    }


    void parse(byte[] payload) throws ProtocolException, IOException {
        // header
        ByteArrayInputStream bis = new ByteArrayInputStream(payload);

        version = Utils.readUint32FromStream(bis);
        prevBlockHash = Sha256Hash.wrapReversed(bis.readNBytes(32));
        merkleRoot = Sha256Hash.wrapReversed(bis.readNBytes(32));
        time = Utils.readUint32FromStream(bis);
        difficultyTarget = Utils.readUint32FromStream(bis);
        nonce = Utils.readUint32FromStream(bis);
        blockHash = Sha256Hash.wrapReversed(Sha256Hash.hashTwice(payload, 0, 80));
//        headerBytesValid = serializer.isParseRetainMode();

        // transactions
        VarInt numTransactionsVarInt = VarInt.fromStream(bis);

        if (numTransactionsVarInt.intValue() <= 0) return;

        optimalEncodingMessageSize = HEADER_SIZE;
        if (payload.length == cursor) {
            // This message is just a header, it has no transactions.
            transactionBytesValid = false;
            return;
        }

        optimalEncodingMessageSize += numTransactionsVarInt.getSizeInBytes();
        int numTransactions = numTransactionsVarInt.intValue();
        transactions = new ArrayList<>(Math.min(numTransactions, Utils.MAX_INITIAL_ARRAY_LENGTH));
        for (int i = 0; i < numTransactions; i++) {
            Transaction tx = Transaction.fromStream(bis);
            transactions.add(tx);
        }
    }

    void writeHeader(OutputStream stream) throws IOException {


        // fall back to manual write
        Utils.uint32ToByteStreamLE(version, stream);
        stream.write(prevBlockHash.getReversedBytes());
        stream.write(getMerkleRoot().getReversedBytes());
        Utils.uint32ToByteStreamLE(time, stream);
        Utils.uint32ToByteStreamLE(difficultyTarget, stream);
        Utils.uint32ToByteStreamLE(nonce, stream);

    }

    protected void unCache() {
        // Since we have alternate uncache methods to use internally this will only ever be called by a child
        // transaction so we only need to invalidate that part of the cache.
        unCacheTransactions();
    }

    private void unCacheHeader() {
        headerBytesValid = false;
        if (!transactionBytesValid)
            payload = null;
        blockHash = null;
    }

    private void unCacheTransactions() {
        transactionBytesValid = false;
        if (!headerBytesValid)
            payload = null;
        // Current implementation has to uncache headers as well as any change to a tx will alter the merkle root. In
        // future we can go more granular and cache merkle root separately so rest of the header does not need to be
        // rewritten.
        unCacheHeader();
        // Clear merkleRoot last as it may end up being parsed during unCacheHeader().
        merkleRoot = null;
    }


    /**
     * Returns the merkle root in big endian form, calculating it from transactions if necessary.
     */
    public Sha256Hash getMerkleRoot() {
        if (merkleRoot == null) {
            //TODO check if this is really necessary.
            unCacheHeader();
            merkleRoot = calculateMerkleRoot();
        }
        return merkleRoot;
    }

    /**
     * Exists only for unit testing.
     */
    void setMerkleRoot(Sha256Hash value) {
        unCacheHeader();
        merkleRoot = value;
        blockHash = null;
    }

    private Sha256Hash calculateMerkleRoot() {
        List<byte[]> tree = buildMerkleTree(false);
        return Sha256Hash.wrap(tree.get(tree.size() - 1));
    }


    private List<byte[]> buildMerkleTree(boolean useWTxId) {
        // The Merkle root is based on a tree of hashes calculated from the transactions:
        //
        //     root
        //      / \
        //   A      B
        //  / \    / \
        // t1 t2 t3 t4
        //
        // The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
        // entry is a hash.
        //
        // The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
        // The interior nodes are hashes of the concatenation of the two child hashes.
        //
        // This structure allows the creation of proof that a transaction was included into a block without having to
        // provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
        // in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
        // derive the root, which can be checked against the block header. These proofs aren't used right now but
        // will be helpful later when we want to download partial block contents.
        //
        // Note that if the number of transactions is not even the last tx is repeated to make it so (see
        // tx3 above). A tree with 5 transactions would look like this:
        //
        //         root
        //        /     \
        //       1        5
        //     /   \     / \
        //    2     3    4  4
        //  / \   / \   / \
        // t1 t2 t3 t4 t5 t5
        ArrayList<byte[]> tree = new ArrayList<>(transactions.size());
        // Start by adding all the hashes of the transactions as leaves of the tree.
        for (Transaction tx : transactions) {
            final Sha256Hash id;
            if (tx.isCoinBase())
                id = Sha256Hash.ZERO_HASH;
            else
                id = Sha256Hash.wrap(tx.getTransactionId());
            tree.add(id.getBytes());
        }
        int levelOffset = 0; // Offset in the list where the currently processed level starts.
        // Step through each level, stopping when we reach the root (levelSize == 1).
        for (int levelSize = transactions.size(); levelSize > 1; levelSize = (levelSize + 1) / 2) {
            // For each pair of nodes on that level:
            for (int left = 0; left < levelSize; left += 2) {
                // The right hand node can be the same as the left hand, in the case where we don't have enough
                // transactions.
                int right = Math.min(left + 1, levelSize - 1);
                byte[] leftBytes = Utils.reverseBytes(tree.get(levelOffset + left));
                byte[] rightBytes = Utils.reverseBytes(tree.get(levelOffset + right));
                tree.add(Utils.reverseBytes(hashTwice(leftBytes, rightBytes)));
            }
            // Move to the next level.
            levelOffset += levelSize;
        }
        return tree;
    }


    /**
     * Calculates the block hash by serializing the block and hashing the
     * resulting bytes.
     */
    public Sha256Hash calculateHash() {
        try {
            ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(HEADER_SIZE);
            writeHeader(bos);
            return Sha256Hash.wrapReversed(Sha256Hash.hashTwice(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e); // Cannot happen.
        }
    }


    /**
     * Returns the hash of the block (which for a valid, solved block should be
     * below the target). Big endian.
     */
    public Sha256Hash getHash() {
        if (blockHash == null)
            blockHash = calculateHash();
        return blockHash;
    }



    @VisibleForTesting
    public void setTransactions(List<Transaction> transactions) {
        unCache();
        this.transactions = transactions;
    }

    /** Returns an immutable list of transactions held in this block, or null if this object represents just a header. */
    @Nullable
    public List<Transaction> getTransactions() {
        return transactions == null ? null : ImmutableList.copyOf(transactions);
    }

    /**
     * Returns the list of transaction id's for this block, building the list if necessary.
     * @return
     */
    public List<Sha256Hash> getTxIds() {
        if (txids == null) {
            if (transactions == null)
                return null;
            List<Sha256Hash> ids = new ArrayList<>(transactions.size());
            for (Transaction t: transactions)
                ids.add(Sha256Hash.wrap(t.getTransactionId()));
            txids = ids;
        }
        return txids;
    }

    public void clearTxids() {
        txids = null;
    }


    private void writeTransactions(OutputStream stream) throws IOException {
        // check for no transaction conditions first
        // must be a more efficient way to do this but I'm tired atm.
        if (transactions == null || transactions.isEmpty()) {
            return;
        }

        // confirmed we must have transactions either cached or as objects.
//        if (transactionBytesValid && payload != null && payload.length >= offset + length()) {
//            stream.write(payload, offset + HEADER_SIZE, length() - HEADER_SIZE);
//            return;
//        }

        if (transactions != null) {
            stream.write(new VarInt(transactions.size()).encode());
            for (Transaction tx : transactions) {
                stream.write(tx.serialize());
            }
        }
    }


    /**
     * Special handling to check if we have a valid byte array for both header
     * and transactions
     *
     */
    public byte[] bitcoinSerialize() {
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream();
        try {
            writeHeader(stream);
            writeTransactions(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        writeHeader(stream);
        // We may only have enough data to write the header.
        writeTransactions(stream);
    }


}
