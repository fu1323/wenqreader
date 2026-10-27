package lab.reader;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.*;

final class Json {
    static final ObjectMapper MAPPER = new ObjectMapper();
    static {
        MAPPER.getFactory().setStreamReadConstraints(
            StreamReadConstraints.builder().maxStringLength(64 * 1024 * 1024).build());
    }
    private Json() {}
    static String compact(JsonNode node) {
        try { return MAPPER.writeValueAsString(node); }
        catch (IOException e) { throw new IllegalArgumentException("JSON 序列化失败"); }
    }
    static JsonNode parse(String text) throws IOException { return MAPPER.readTree(text); }
    static ObjectNode object(JsonNode node, String label) throws IOException {
        if (!(node instanceof ObjectNode object)) throw new IOException(label + " 不是 JSON 对象");
        return object;
    }
    static void write(Path path, Object value) throws IOException {
        Files.writeString(path, MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n",
            StandardOpenOption.CREATE_NEW);
    }
}
