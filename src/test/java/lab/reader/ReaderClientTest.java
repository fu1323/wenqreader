package lab.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.sun.net.httpserver.HttpServer;
import okhttp3.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

class ReaderClientTest {
    @TempDir Path temp;
    private static final String FP = "0123456789abcdef0123456789abcdef";
    private static final Clock FIXED = Clock.fixed(Instant.ofEpochMilli(1793081947000L), ZoneOffset.UTC);
    private record Seen(String uri, String cookie, String requestId) {}

    private static final class Stub implements AutoCloseable {
        final HttpServer server;
        final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger position = new AtomicInteger();
        final JsonNode entries;
        final int rejectAt;
        final boolean redirect;
        Stub(int rejectAt, boolean redirect) throws Exception {
            entries = ProtocolTest.resource("synthetic.har.json").path("log").path("entries");
            this.rejectAt = rejectAt;
            this.redirect = redirect;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                int n = position.getAndIncrement();
                seen.add(new Seen(exchange.getRequestURI().toString(),
                    exchange.getRequestHeaders().getFirst("Cookie"),
                    exchange.getRequestHeaders().getFirst("RequestID")));
                byte[] body; int status = 200;
                if (redirect) {
                    exchange.getResponseHeaders().add("Location", "/unexpected");
                    status = 302; body = new byte[0];
                } else if (n == rejectAt) {
                    body = "{\"code\":40109,\"data\":null}".getBytes(UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                } else if (n >= entries.size()) {
                    status = 500; body = new byte[0];
                } else {
                    JsonNode e = entries.get(n);
                    body = HarVerifier.body(e);
                    exchange.getResponseHeaders().add("Content-Type", e.path("response").path("content").path("mimeType").asText());
                }
                exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
                if (body.length > 0) exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();
        }
        HttpUrl origin() { return HttpUrl.get("http://127.0.0.1:" + server.getAddress().getPort() + "/"); }
        @Override public void close() { server.stop(0); }
    }
    private static BrowserSession session(HttpUrl origin) {
        return new BrowserSession(origin, "gidf=" + FP + "; PHPSESSID=synthetic-session", "SyntheticBrowser/1", "0", "", "");
    }

    @Test void okhttpCompletesPageAndRequestsMatchIndependentFixture() throws Exception {
        try (Stub stub = new Stub(-1, false);
             ReaderClient client = new ReaderClient(stub.origin(), session(stub.origin()), FIXED)) {
            client.fetchPage(7, 1, null, "images", temp);
            assertEquals(7, stub.seen.size());
            for (int i = 0; i < stub.seen.size(); i++) {
                URI expected = URI.create(stub.entries.get(i).path("request").path("url").asText());
                assertEquals(expected.getRawPath() + "?" + expected.getRawQuery(), stub.seen.get(i).uri(), "request " + i);
                assertTrue(stub.seen.get(i).cookie().contains("gidf=" + FP));
            }
            assertEquals("0", stub.seen.get(2).requestId());
            assertTrue(Files.exists(temp.resolve("fragment-000.png")));
            assertTrue(Files.exists(temp.resolve("fragment-001.png")));
            JsonNode manifest = Json.MAPPER.readTree(temp.resolve("manifest.json").toFile());
            assertTrue(manifest.path("completed").asBoolean());
            assertEquals(2, manifest.path("fragments").size());
            String trace = Files.readString(temp.resolve("trace.json"));
            assertFalse(trace.contains(FP));
            assertFalse(trace.contains("synthetic-session"));
            assertFalse(trace.contains("synthetic-user"));
        }
    }
    @Test void businessErrorStopsBeforeFurtherCredentialsOrImages() throws Exception {
        try (Stub stub = new Stub(3, false);
             ReaderClient client = new ReaderClient(stub.origin(), session(stub.origin()), FIXED)) {
            ProtocolException error = assertThrows(ProtocolException.class,
                () -> client.fetchPage(7, 1, null, "images", temp));
            assertEquals("once/get", error.stage());
            assertEquals(40109, error.code());
            assertEquals(4, stub.seen.size());
            assertFalse(Json.MAPPER.readTree(temp.resolve("manifest.json").toFile()).path("completed").asBoolean());
        }
    }
    @Test void redirectsAreNotFollowed() throws Exception {
        try (Stub stub = new Stub(-1, true);
             ReaderClient client = new ReaderClient(stub.origin(), session(stub.origin()), FIXED)) {
            var error = assertThrows(ProtocolException.class, () -> client.fetchPage(7, 1, null, "images", temp));
            assertEquals(302, error.code());
            assertEquals(1, stub.seen.size());
        }
    }
    @Test void canStopAtPreviewWithoutRequestingCredentials() throws Exception {
        try (Stub stub = new Stub(-1, false);
             ReaderClient client = new ReaderClient(stub.origin(), session(stub.origin()), FIXED)) {
            client.fetchPage(7, 1, null, "preview", temp);
            assertEquals(3, stub.seen.size());
            assertTrue(Files.exists(temp.resolve("preview.png")));
        }
    }
    @Test void updatedCookiesStayHostScopedAndExpiredCookiesDisappear() {
        HttpUrl origin = HttpUrl.get("https://wqbook.wqxuetang.com/");
        BrowserSession jar = session(origin);
        Cookie update = Cookie.parse(origin, "PHPSESSID=new-session; Path=/; Secure");
        jar.saveFromResponse(origin, List.of(Objects.requireNonNull(update)));
        assertTrue(jar.loadForRequest(origin).stream().anyMatch(c -> c.name().equals("PHPSESSID") && c.value().equals("new-session")));
        assertTrue(jar.loadForRequest(HttpUrl.get("https://example.invalid/")).isEmpty());
        Cookie remove = Cookie.parse(origin, "PHPSESSID=; Max-Age=0; Path=/; Secure");
        jar.saveFromResponse(origin, List.of(Objects.requireNonNull(remove)));
        assertFalse(jar.loadForRequest(origin).stream().anyMatch(c -> c.name().equals("PHPSESSID")));
    }
}
