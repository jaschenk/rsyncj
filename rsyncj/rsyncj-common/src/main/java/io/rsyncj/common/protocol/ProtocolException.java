package io.rsyncj.common.protocol;

/** Thrown when the peer violates the wire protocol or a transfer fails validation. */
public class ProtocolException extends RuntimeException {
    public ProtocolException(String message) {
        super(message);
    }

    public ProtocolException(String message, Throwable cause) {
        super(message, cause);
    }
}
