package lab.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import okhttp3.HttpUrl;
import java.io.*;
import java.nio.file.Path;
import java.util.*;
import static java.nio.charset.StandardCharsets.*;

/** Entirely offline. Rebuilds successful request parameters from their upstream responses. */
public final class HarVerifier {
    private final ReaderProtocol protocol = new ReaderProtocol();
    private record Credential(long bid, ObjectNode value, int index) {}
    private record Meta(ReaderProtocol.Preview value, int index) {}
    private record Temporary(long bid, String page, String fp, int fragment, ObjectNode value,
                             String salt, int index, int baseIndex, int previewIndex) {}
    public ObjectNode verify(Path path) throws IOException {
        JsonNode entries = Json.MAPPER.readTree(path.toFile()).path("log").path("entries");
        if (!entries.isArray()) throw new IOException("文件不是含 log.entries 的 HAR");
        List<Credential> credentials = new ArrayList<>();
        Map<String, Meta> metadata = new HashMap<>();
        List<Temporary> temporary = new ArrayList<>();
        ObjectNode report = Json.MAPPER.createObjectNode();
        report.put("mode", "offline").put("totalEntries", entries.size());
        report.put("timestampPolicy", "使用捕获的时间戳；不把请求开始时间当成加密时刻");
        ArrayNode checks = report.putArray("checks"), observations = report.putArray("observations");
        ArrayNode failures = report.putArray("failures"), incomplete = report.putArray("incomplete");
        int smallCount = 0, onceCount = 0, lmgCount = 0, onceCaptured = 0, lmgCaptured = 0;
        for (int index = 0; index < entries.size(); index++) {
            JsonNode entry = entries.get(index);
            HttpUrl url = HttpUrl.parse(entry.path("request").path("url").asText());
            if (url == null) continue;
            String p = url.encodedPath();
            boolean read = p.equals("/api/v7/read/k"), small = p.startsWith("/deep/page/imgs/");
            boolean once = p.equals("/deep/page/once/get"), lmg = p.startsWith("/deep/page/lmg/");
            if (!read && !small && !once && !lmg) continue;
            if (entry.path("response").path("status").asInt() != 200) {
                observations.addObject().put("entry", index).put("path", p).put("note", "HTTP 未成功；单独记录");
                continue;
            }
            try {
                byte[] bytes = body(entry);
                if (read) {
                    JsonNode response = Json.parse(new String(bytes, UTF_8));
                    if (response.path("code").asInt(-1) == 0)
                        credentials.add(new Credential(Long.parseLong(required(url, "bid")),
                            Json.object(response.get("data"), "基础凭据"), index));
                    continue;
                }
                String fp = fingerprint(entry);
                if (small) {
                    long bid = pathBook(url); String page = pathPage(url);
                    String keyJson = new String(Base64.getDecoder().decode(required(url, "k")), ISO_8859_1);
                    Credential base = findBase(credentials, bid, keyJson);
                    if (base == null) throw new MissingEvidence("缺少与小图 k 对应的 read/k 成功响应");
                    ReaderProtocol.Preview preview = protocol.parsePreview(bytes, fp, Integer.parseInt(page));
                    metadata.put(metaKey(bid, page, fp), new Meta(preview, index));
                    checks.addObject().put("entry", index).put("stage", "imgs").put("bookId", bid).put("page", page)
                        .put("baseEntry", base.index()).put("kMatchesBase", true).put("width", required(url, "width"))
                        .put("fragmentCount", preview.fragments().size()).put("metadataBytes", preview.metadataBytes());
                    smallCount++;
                    continue;
                }
                if (once) {
                    JsonNode response = Json.parse(new String(bytes, UTF_8));
                    if (response.path("code").asInt(-1) != 0) {
                        ObjectNode observation = observations.addObject().put("entry", index).put("path", p)
                            .put("code", response.path("code").asInt(-1)).put("outerPage", required(url, "pnum"))
                            .put("note", "业务失败请求单独记录，不计入成功链路，也不推断错误码语义");
                        try {
                            JsonNode payload = Json.parse(protocol.decrypt(ReaderProtocol.decodeUri(required(url, "k")), fp, 1));
                            observation.put("encryptedPage", payload.path("p").asText());
                        } catch (Exception ignored) { observation.put("encryptedPage", "未能解析"); }
                        continue;
                    }
                    onceCaptured++;
                    long bid = Long.parseLong(required(url, "bid")); String page = required(url, "pnum");
                    ObjectNode payload = Json.object(Json.parse(protocol.decrypt(ReaderProtocol.decodeUri(required(url, "k")), fp, 1)), "once 载荷");
                    checkPayload(payload, bid, page);
                    Credential base = findBase(credentials, bid, payload.path("k").asText());
                    if (base == null) throw new MissingEvidence("缺少与 once 内层 k 对应的 read/k 响应");
                    Meta meta = metadata.get(metaKey(bid, page, fp));
                    if (meta == null) throw new MissingEvidence("缺少同一页和指纹的预览元数据");
                    if (!payload.path("zn").isIntegralNumber()) throw new IOException("once 分片编号类型与抓包版本不符");
                    int fragment = payload.path("zn").intValue();
                    if (!meta.value().fragments().contains(fragment)) throw new IOException("once 分片不在预览数组中");
                    ObjectNode rebuilt = protocol.oncePayload(bid, page, payload.path("t").longValue(), base.value(), fragment);
                    HttpUrl expected = ReaderProtocol.onceUrl(url, bid, page, protocol.encrypt(Json.compact(rebuilt), fp));
                    if (!rawK(expected).equals(rawK(url))) throw new IOException("once 原始 k 与上游重算值不同");
                    ObjectNode temp = protocol.decryptTemporary(response.path("data").asText(), base.value());
                    temporary.add(new Temporary(bid, page, fp, fragment, temp, meta.value().salt(), index, base.index(), meta.index()));
                    checks.addObject().put("entry", index).put("stage", "once/get").put("page", page)
                        .put("fragmentId", fragment).put("baseEntry", base.index()).put("previewEntry", meta.index())
                        .put("encodedKExact", true).put("aesDecoded", true).put("uriEncodingLayers", 2);
                    onceCount++;
                    continue;
                }
                if (lmg) {
                    lmgCaptured++;
                    ReaderProtocol.imageExtension(bytes);
                    long bid = pathBook(url); String page = pathPage(url);
                    ObjectNode payload = Json.object(Json.parse(protocol.decrypt(required(url, "k"), fp, 1)), "lmg 载荷");
                    checkPayload(payload, bid, page);
                    String innerJson = payload.path("k").asText();
                    ObjectNode inner = Json.object(Json.parse(innerJson), "lmg 内层凭据");
                    Temporary match = null; ObjectNode signed = null;
                    for (int n = temporary.size() - 1; n >= 0; n--) {
                        Temporary t = temporary.get(n);
                        if (t.bid() != bid || !t.page().equals(page) || !t.fp().equals(fp)) continue;
                        ObjectNode candidate = protocol.finishTemporary(t.value(), t.salt(), inner.path("w").asText(""));
                        if (Json.compact(candidate).equals(innerJson)) { match = t; signed = candidate; break; }
                    }
                    if (match == null) {
                        boolean hasCandidate = temporary.stream().anyMatch(t -> t.bid() == bid && t.page().equals(page) && t.fp().equals(fp));
                        if (!hasCandidate) throw new MissingEvidence("缺少对应 once/get 上游响应");
                        throw new IOException("临时凭据或 MD5 与上游重算值不同");
                    }
                    ObjectNode rebuilt = protocol.finalPayload(bid, page, payload.path("t").longValue(), signed);
                    String volume = url.queryParameter("v");
                    HttpUrl expected = ReaderProtocol.imageUrl(url, bid, page, volume == null ? null : Integer.valueOf(volume),
                        protocol.encrypt(Json.compact(rebuilt), fp));
                    if (!rawK(expected).equals(rawK(url))) throw new IOException("lmg 原始 k 与上游重算值不同");
                    checks.addObject().put("entry", index).put("stage", "lmg").put("page", page)
                        .put("fragmentId", match.fragment()).put("onceEntry", match.index())
                        .put("previewEntry", match.previewIndex()).put("baseEntry", match.baseIndex())
                        .put("md5Verified", true).put("encodedKExact", true).put("bytes", bytes.length).put("uriEncodingLayers", 1);
                    lmgCount++;
                }
            } catch (MissingEvidence e) {
                incomplete.addObject().put("entry", index).put("path", p).put("reason", e.getMessage());
            } catch (ProtocolException e) {
                observations.addObject().put("entry", index).put("path", p).put("code", e.code()).put("note", "预览业务状态失败，单独记录");
            } catch (Exception e) {
                failures.addObject().put("entry", index).put("path", p)
                    .put("reason", "无法按已验证版本重建（" + e.getClass().getSimpleName() + "）");
            }
        }
        report.put("baseResponses", credentials.size()).put("previewsVerified", smallCount)
            .put("onceSuccessfulCaptured", onceCaptured).put("onceVerified", onceCount)
            .put("lmgSuccessfulCaptured", lmgCaptured).put("lmgVerified", lmgCount)
            .put("passed", onceCount > 0 && lmgCount > 0 && onceCount == onceCaptured && lmgCount == lmgCaptured
                && failures.isEmpty() && incomplete.isEmpty());
        return report;
    }
    private static void checkPayload(ObjectNode payload, long bid, String page) throws IOException {
        if (!payload.path("p").isTextual() || !payload.path("p").asText().equals(page)
            || payload.path("b").asLong(-1) != bid || payload.path("w").asInt(-1) != 1000
            || !payload.path("t").isIntegralNumber() || !payload.path("k").isTextual())
            throw new IOException("外层参数与加密载荷不对应");
    }
    static byte[] body(JsonNode entry) throws IOException {
        JsonNode content = entry.path("response").path("content");
        if (!content.has("text")) throw new MissingEvidence("HAR 未包含响应体");
        String text = content.path("text").asText();
        return content.path("encoding").asText().equals("base64") ? Base64.getDecoder().decode(text) : text.getBytes(UTF_8);
    }
    private static Credential findBase(List<Credential> credentials, long bid, String json) {
        for (int n = credentials.size() - 1; n >= 0; n--) {
            Credential c = credentials.get(n);
            if (c.bid() == bid && Json.compact(c.value()).equals(json)) return c;
        }
        return null;
    }
    static String fingerprint(JsonNode entry) throws IOException {
        for (JsonNode c : entry.path("request").path("cookies"))
            if (c.path("name").asText().equals("gidf")) return ReaderProtocol.decodeUri(c.path("value").asText());
        for (JsonNode h : entry.path("request").path("headers")) {
            if (!h.path("name").asText().equalsIgnoreCase("cookie")) continue;
            for (String pair : h.path("value").asText().split(";")) {
                String part = pair.trim();
                if (part.startsWith("gidf=")) return ReaderProtocol.decodeUri(part.substring(5));
            }
        }
        throw new MissingEvidence("HAR 缺少 gidf Cookie");
    }
    private static String required(HttpUrl url, String key) throws IOException {
        String value = url.queryParameter(key);
        if (value == null) throw new IOException("缺少参数 " + key);
        return value;
    }
    private static long pathBook(HttpUrl url) { return Long.parseLong(url.pathSegments().get(3)); }
    private static String pathPage(HttpUrl url) { return url.pathSegments().get(4); }
    private static String metaKey(long bid, String page, String fp) { return bid + "/" + page + "/" + fp; }
    private static String rawK(HttpUrl url) throws IOException {
        if (url.encodedQuery() != null)
            for (String pair : url.encodedQuery().split("&")) if (pair.startsWith("k=")) return pair.substring(2);
        throw new IOException("查询串缺少 k");
    }
    private static final class MissingEvidence extends IOException {
        MissingEvidence(String message) { super(message); }
    }
}
