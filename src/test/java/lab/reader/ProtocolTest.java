package lab.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import okhttp3.HttpUrl;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class ProtocolTest {
    @TempDir Path temp;
    static JsonNode resource(String name) throws Exception {
        try (var in = ProtocolTest.class.getResourceAsStream("/" + name)) {
            return Json.MAPPER.readTree(Objects.requireNonNull(in));
        }
    }
    @Test void matchesIndependentNodeChaChaVectorsIncludingUtf8() throws Exception {
        JsonNode v = resource("vectors.json");
        ReaderProtocol p = new ReaderProtocol();
        assertEquals(v.path("counter1").asText(), p.encrypt(v.path("plaintext").asText(), v.path("fingerprint").asText()));
        assertEquals(v.path("plaintext").asText(), p.decrypt(v.path("counter5").asText(), v.path("fingerprint").asText(), 5));
    }
    @Test void queryEncodingKeepsPlusAndUsesOneVsTwoLayers() {
        HttpUrl base = HttpUrl.get("https://example.invalid/");
        String b64 = "a+/=";
        assertEquals("bid=7&pnum=1&k=a%252B%252F%253D", ReaderProtocol.onceUrl(base, 7, "1", b64).encodedQuery());
        assertEquals("k=a%2B%2F%3D", ReaderProtocol.imageUrl(base, 7, "1", null, b64).encodedQuery());
        assertEquals("a+/=", ReaderProtocol.decodeUri("a%2B%2F%3D"));
        assertEquals("!~*'()%20%2B%2F", ReaderProtocol.encodeUri("!~*'() +/"));
    }
    @Test void parsesEncryptedPreviewAndRejectsMalformedLengthOrBusinessError() throws Exception {
        JsonNode har = resource("synthetic.har.json"), v = resource("vectors.json");
        byte[] bytes = HarVerifier.body(har.path("log").path("entries").get(2));
        ReaderProtocol p = new ReaderProtocol();
        var preview = p.parsePreview(bytes, v.path("fingerprint").asText(), 1);
        assertEquals(List.of(1, 0), preview.fragments());
        assertEquals("png", preview.extension());
        byte[] broken = bytes.clone();
        Arrays.fill(broken, broken.length - 4, broken.length, (byte)255);
        assertThrows(java.io.IOException.class, () -> p.parsePreview(broken, v.path("fingerprint").asText(), 1));
        int m = java.nio.ByteBuffer.wrap(bytes, bytes.length - 4, 4).getInt(), offset = bytes.length - 4 - m - 6;
        byte[] denied = bytes.clone();
        denied[offset] = (byte)(40306 >>> 8); denied[offset + 1] = (byte)40306;
        var error = assertThrows(ProtocolException.class, () -> p.parsePreview(denied, v.path("fingerprint").asText(), 1));
        assertEquals(40306, error.code());
    }
    @Test void offlineVerifierRebuildsFullSyntheticChain() throws Exception {
        Path file = temp.resolve("fixture.json");
        Files.writeString(file, Json.compact(resource("synthetic.har.json")));
        ObjectNode result = new HarVerifier().verify(file);
        assertTrue(result.path("passed").asBoolean(), result.toString());
        assertEquals(2, result.path("onceVerified").asInt());
        assertEquals(2, result.path("lmgVerified").asInt());
    }
    @Test void modifiedFailedRequestIsObservationNotNormalChainFailure() throws Exception {
        ObjectNode har = (ObjectNode)resource("synthetic.har.json");
        ArrayNode entries = (ArrayNode)har.path("log").path("entries");
        ObjectNode modified = entries.get(3).deepCopy();
        ((ObjectNode)modified.get("request")).put("url",
            modified.path("request").path("url").asText().replace("pnum=1&", "pnum=120&"));
        ((ObjectNode)modified.path("response").path("content")).put("text", "{\"code\":40109,\"data\":null}");
        entries.add(modified);
        Path file = temp.resolve("modified.json");
        Files.writeString(file, Json.compact(har));
        ObjectNode result = new HarVerifier().verify(file);
        assertTrue(result.path("passed").asBoolean(), result.toString());
        assertEquals(1, result.path("observations").size());
        assertEquals("120", result.path("observations").get(0).path("outerPage").asText());
        assertEquals("1", result.path("observations").get(0).path("encryptedPage").asText());
    }
    @Test void detectsTamperedMd5EvenWhenCipherRoundtripWouldPass() throws Exception {
        ObjectNode har = (ObjectNode)resource("synthetic.har.json");
        JsonNode vectors = resource("vectors.json");
        ((ObjectNode)har.path("log").path("entries").get(5).path("request"))
            .put("url", vectors.path("tamperedLmgUrl").asText());
        Path file = temp.resolve("tampered.json");
        Files.writeString(file, Json.compact(har));
        ObjectNode result = new HarVerifier().verify(file);
        assertFalse(result.path("passed").asBoolean());
        assertEquals(1, result.path("failures").size());
        assertEquals(1, result.path("lmgVerified").asInt());
    }
    @Test void incompleteHarCannotReportSuccess() throws Exception {
        ObjectNode har = (ObjectNode)resource("synthetic.har.json");
        ((ObjectNode)har.path("log").path("entries").get(1).path("response").path("content")).remove("text");
        Path file = temp.resolve("missing.json");
        Files.writeString(file, Json.compact(har));
        ObjectNode result = new HarVerifier().verify(file);
        assertFalse(result.path("passed").asBoolean());
        assertFalse(result.path("incomplete").isEmpty());
    }
}
