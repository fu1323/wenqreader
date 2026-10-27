package lab.reader;

import com.fasterxml.jackson.databind.JsonNode;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.HttpUrl;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

public final class BrowserSession implements CookieJar {
    private final List<Cookie> cookies = new ArrayList<>();
    final String userAgent, requestId, accessToken, frameUrl;

    public BrowserSession(HttpUrl origin, String cookieHeader, String userAgent,
                          String requestId, String accessToken, String frameUrl) {
        if (cookieHeader == null || cookieHeader.contains("REPLACE_") || cookieHeader.contains("\n") || cookieHeader.contains("\r"))
            throw new IllegalArgumentException("请填写当前浏览器的完整单行 Cookie");
        if (userAgent == null || userAgent.isBlank() || userAgent.contains("REPLACE_"))
            throw new IllegalArgumentException("请填写浏览器 User-Agent");
        if (requestId == null || !requestId.matches("-?[0-9]+"))
            throw new IllegalArgumentException("requestId 应来自浏览器的 RequestID 请求头；本次访客抓包为 0");
        String header = cookieHeader.trim();
        if (header.regionMatches(true, 0, "Cookie:", 0, 7)) header = header.substring(7).trim();
        for (String part : header.split(";")) {
            Cookie cookie = Cookie.parse(origin, part.trim() + "; Path=/" + (origin.isHttps() ? "; Secure" : ""));
            if (cookie == null) throw new IllegalArgumentException("Cookie 格式无效");
            cookies.add(cookie);
        }
        this.userAgent = userAgent;
        this.requestId = requestId;
        this.accessToken = accessToken == null ? "" : accessToken;
        this.frameUrl = frameUrl == null ? "" : frameUrl;
        if (fingerprint(origin).isBlank()) throw new IllegalArgumentException("Cookie 中缺少 gidf；请先在浏览器打开阅读器");
    }
    public static BrowserSession load(Path file, HttpUrl origin) throws IOException {
        JsonNode node = Json.MAPPER.readTree(file.toFile());
        return new BrowserSession(origin, node.path("cookie").asText(), node.path("userAgent").asText(),
            node.path("requestId").asText("0"), node.path("accessToken").asText(""), node.path("frameUrl").asText(""));
    }
    @Override public synchronized void saveFromResponse(HttpUrl url, List<Cookie> incoming) {
        for (Cookie fresh : incoming) {
            cookies.removeIf(old -> old.name().equals(fresh.name()) && old.domain().equals(fresh.domain()) && old.path().equals(fresh.path()));
            if (fresh.expiresAt() > System.currentTimeMillis()) cookies.add(fresh);
        }
    }
    @Override public synchronized List<Cookie> loadForRequest(HttpUrl url) {
        cookies.removeIf(cookie -> cookie.expiresAt() <= System.currentTimeMillis());
        return cookies.stream().filter(cookie -> cookie.matches(url)).toList();
    }
    public synchronized String fingerprint(HttpUrl url) {
        return loadForRequest(url).stream().filter(c -> c.name().equals("gidf")).findFirst()
            .map(c -> ReaderProtocol.decodeUri(c.value())).orElse("");
    }
}
