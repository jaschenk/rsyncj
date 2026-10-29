package io.rsyncj.common.protocol;

/** Wire frame kinds. */
public enum FrameType {
    /** UTF-8 JSON control message. */
    JSON(1),
    /** Raw file bytes belonging to the file currently being transferred. */
    DATA(2);

    private final int code;

    FrameType(int code) {
        this.code = code;
    }

    public int code() {
        return code;
    }

    public static FrameType of(int code) {
        return switch (code) {
            case 1 -> JSON;
            case 2 -> DATA;
            default -> throw new ProtocolException("Unknown frame type: " + code);
        };
    }
}
