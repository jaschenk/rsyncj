package io.rsyncj.common.json;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/** Shared, pre-configured Jackson mappers. */
public final class Json {

    /** Compact mapper used on the wire and for persisted state. */
    public static final ObjectMapper MAPPER = new ObjectMapper();

    /** Human friendly mapper used by the CLI. */
    public static final ObjectMapper PRETTY = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private Json() {
    }
}
