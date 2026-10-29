package io.rsyncj.common.protocol;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rsyncj.common.json.Json;

import java.io.IOException;
import java.io.OutputStream;

/** Helpers for the JSON control channel. */
public final class Messages {

    private Messages() {
    }

    public static ObjectNode of(String type) {
        return Json.MAPPER.createObjectNode().put("type", type);
    }

    public static void send(OutputStream out, ObjectNode message) throws IOException {
        FrameIO.write(out, FrameType.JSON, Json.MAPPER.writeValueAsBytes(message));
    }

    public static ObjectNode parse(FrameIO.Frame frame) {
        if (frame.type() != FrameType.JSON) {
            throw new ProtocolException("Expected JSON control frame but got " + frame.type());
        }
        try {
            var node = Json.MAPPER.readTree(frame.payload());
            if (!node.isObject()) {
                throw new ProtocolException("Control frame is not a JSON object");
            }
            return (ObjectNode) node;
        } catch (IOException e) {
            throw new ProtocolException("Malformed JSON control frame", e);
        }
    }

    public static String typeOf(ObjectNode message) {
        var type = message.get("type");
        if (type == null || !type.isTextual()) {
            throw new ProtocolException("Control message without a type");
        }
        return type.asText();
    }

    /** Sends an error message. Callers normally close the connection afterwards. */
    public static void sendError(OutputStream out, String code, String message) {
        try {
            send(out, of("error").put("code", code).put("message", message));
            out.flush();
        } catch (IOException ignored) {
            // peer already gone
        }
    }
}
