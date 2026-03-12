package org.twostack.bitcoin4j.script;

/**
 * Script info for B:// protocol data scripts.
 */
public class BProtocolScriptInfo extends ScriptInfo {

    private final byte[] data;
    private final String mediaType;
    private final String encoding;
    private final String filename;

    public BProtocolScriptInfo(byte[] data, String mediaType, String encoding, String filename) {
        super("BProtocol");
        this.data = data;
        this.mediaType = mediaType;
        this.encoding = encoding;
        this.filename = filename;
    }

    public byte[] getData() {
        return data;
    }

    public String getMediaType() {
        return mediaType;
    }

    public String getEncoding() {
        return encoding;
    }

    public String getFilename() {
        return filename;
    }
}
