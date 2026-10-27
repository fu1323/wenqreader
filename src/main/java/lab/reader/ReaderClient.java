package lab.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import okhttp3.*;
import java.io.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import static java.nio.charset.StandardCharsets.UTF_8;

/** One page per invocation; intermediate trace contains no credentials or complete signed URLs. */
public final class ReaderClient implements AutoCloseable {
    private static final int MAX_BODY = 64 * 1024 * 1024;
    private final HttpUrl origin;
    private final BrowserSession session;
    private final OkHttpClient http;
    private final Clock clock;
    private final ReaderProtocol protocol = new ReaderProtocol();
    private final ArrayNode trace = Json.MAPPER.createArrayNode();

    public ReaderClient(HttpUrl origin, BrowserSession session, Clock clock) {
        this.origin = origin;
        this.session = session;
        this.clock = clock;
        http = new OkHttpClient.Builder().cookieJar(session)
            .connectTimeout(Duration.ofSeconds(20)).readTimeout(Duration.ofSeconds(45))
            .callTimeout(Duration.ofSeconds(60)).retryOnConnectionFailure(false)
            .followRedirects(false).followSslRedirects(false).build();
    }
    private void event(String stage, String message) {
        trace.addObject().put("stage", stage).put("message", message).put("at", clock.instant().toString());
        System.out.println("[" + stage + "] " + message);
    }
    private HttpUrl.Builder url(String path, long bid, Integer volume, String volumeParam) {
        HttpUrl.Builder b = origin.newBuilder().encodedPath(path).query(null).addQueryParameter("bid", Long.toString(bid));
        if (volume != null) b.addQueryParameter(volumeParam, volume.toString());
        if (!session.accessToken.isEmpty()) b.addQueryParameter("access_token", session.accessToken);
        return b;
    }
    private byte[] get(String stage, HttpUrl url, long bid, boolean preview) throws IOException {
        Request.Builder builder = new Request.Builder().url(url).get()
            .header("User-Agent", session.userAgent)
            .header("Referer", origin.resolve("/deep/read/pdf?bid=" + bid).toString())
            .header("Accept", preview || stage.equals("lmg") ? "image/avif,image/webp,image/*,*/*;q=0.8" : "application/json, text/plain, */*");
        if (preview) builder.header("RequestID", session.requestId);
        try (Response response = http.newCall(builder.build()).execute()) {
            if (!response.isSuccessful())
                throw new ProtocolException(stage, response.code(), "HTTP 请求未成功；重定向、鉴权失败等情况不会自动重试");
            ResponseBody body = response.body();
            if (body == null) throw new ProtocolException(stage, -1, "响应体为空");
            if (body.contentLength() > MAX_BODY) throw new ProtocolException(stage, -1, "响应超过 64 MiB 上限");
            byte[] bytes = body.byteStream().readNBytes(MAX_BODY + 1);
            if (bytes.length > MAX_BODY) throw new ProtocolException(stage, -1, "响应超过 64 MiB 上限");
            event(stage, "HTTP " + response.code() + "，" + bytes.length + " 字节");
            String mime = response.header("Content-Type", "").toLowerCase(Locale.ROOT);
            if (preview || stage.equals("lmg")) {
                if (mime.contains("json")) {
                    JsonNode error = Json.parse(new String(bytes, UTF_8));
                    throw new ProtocolException(stage, error.path("code").asInt(-1), "图片接口返回 JSON，已停止");
                }
                if (mime.contains("html")) throw new ProtocolException(stage, -1, "图片接口返回 HTML，可能需要重新登录或完成验证");
            }
            return bytes;
        } catch (ProtocolException e) { throw e; }
        catch (IOException e) {
            // OkHttp errors may include URLs. Do not expose a query carrying k or access_token.
            throw new ProtocolException(stage, -1, "网络或响应读取失败（" + e.getClass().getSimpleName() + "）");
        }
    }
    private JsonNode data(String stage, HttpUrl url, long bid) throws IOException {
        JsonNode body;
        try { body = Json.parse(new String(get(stage, url, bid, false), UTF_8)); }
        catch (com.fasterxml.jackson.core.JacksonException e) { throw new ProtocolException(stage, -1, "响应不是预期 JSON"); }
        if (body == null || !body.has("code") || body.path("code").asInt(-1) != 0)
            throw new ProtocolException(stage, body == null ? -1 : body.path("code").asInt(-1), "服务端业务校验失败，已停止");
        if (!body.hasNonNull("data")) throw new ProtocolException(stage, -1, "成功响应缺少 data");
        return body.get("data");
    }
    private long timestamp() { return Math.floorDiv(clock.millis(), 1000) * 1000; }
    private void requireFingerprint(String expected) throws ProtocolException {
        if (!expected.equals(session.fingerprint(origin)))
            throw new ProtocolException("session", -1, "执行期间 gidf 发生变化，请用新的浏览器会话重新开始");
    }
    private record Pending(int fragment, HttpUrl url) {}

    public void fetchPage(long bid, int page, Integer volume, String stopAfter, Path output) throws Exception {
        if (bid <= 0 || page < 1 || volume != null && volume < 1) throw new IllegalArgumentException("书号、页码、分册号必须为正整数");
        if (!List.of("base", "preview", "credentials", "images").contains(stopAfter))
            throw new IllegalArgumentException("stop-after 只能为 base、preview、credentials、images");
        ObjectNode manifest = Json.MAPPER.createObjectNode();
        manifest.put("bookId", bid).put("page", page).put("completed", false).put("stopAfter", stopAfter);
        ArrayNode files = manifest.putArray("fragments");
        try {
            JsonNode info = data("initread", url("/api/v7/read/initread", bid, volume, "num").build(), bid);
            manifest.put("canread", info.path("canread").asInt(-1))
                .put("canreadpages", info.path("canreadpages").asInt(-1)).put("bookPages", info.path("pages").asInt(-1));
            event("initread", "canread=" + info.path("canread").asInt(-1) + "，canreadpages=" + info.path("canreadpages").asInt(-1));
            int pages = info.path("pages").asInt(0);
            if (pages > 0 && page > pages) throw new ProtocolException("initread", -1, "页码超过图书页数");
            if (info.path("pdfepub").asInt(0) == 1) throw new ProtocolException("initread", -1, "该书使用另一版本阅读器，本示例不适用");
            ObjectNode base = Json.object(data("read/k", url("/api/v7/read/k", bid, volume, "volume_no").build(), bid), "基础凭据");
            event("read/k", "已取得基础凭据；字段数 " + base.size());
            if (stopAfter.equals("base")) { manifest.put("completed", true); return; }
            String fp = session.fingerprint(origin), p = Integer.toString(page);
            HttpUrl.Builder small = origin.newBuilder().encodedPath("/deep/page/imgs/" + bid + "/" + p).query(null);
            if (volume != null) small.addQueryParameter("v", volume.toString());
            small.addQueryParameter("width", "160").addQueryParameter("k", protocol.smallKey(base));
            ReaderProtocol.Preview preview = protocol.parsePreview(get("imgs", small.build(), bid, true), fp, page);
            Files.write(output.resolve("preview." + preview.extension()), preview.image(), StandardOpenOption.CREATE_NEW);
            manifest.set("fragmentOrder", Json.MAPPER.valueToTree(preview.fragments()));
            manifest.set("geometry", Json.MAPPER.valueToTree(preview.geometry()));
            manifest.put("preview", "preview." + preview.extension());
            event("imgs", "解析成功；分片顺序 " + preview.fragments() + "，元数据 " + preview.metadataBytes() + " 字节");
            if (stopAfter.equals("preview")) { manifest.put("completed", true); return; }

            List<Pending> pending = new ArrayList<>();
            for (int fragment : preview.fragments()) {
                requireFingerprint(fp);
                ObjectNode payload = protocol.oncePayload(bid, p, timestamp(), base, fragment);
                String ciphertext = protocol.encrypt(Json.compact(payload), fp);
                JsonNode once = data("once/get", ReaderProtocol.onceUrl(origin, bid, p, ciphertext), bid);
                if (!once.isTextual()) throw new ProtocolException("once/get", -1, "临时凭据不是字符串");
                ObjectNode temp = protocol.decryptTemporary(once.textValue(), base);
                ObjectNode signed = protocol.finishTemporary(temp, preview.salt(), session.frameUrl);
                ObjectNode finalPayload = protocol.finalPayload(bid, p, timestamp(), signed);
                String finalCiphertext = protocol.encrypt(Json.compact(finalPayload), fp);
                pending.add(new Pending(fragment, ReaderProtocol.imageUrl(origin, bid, p, volume, finalCiphertext)));
                event("credential", "分片 " + fragment + "：AES 解密、MD5、最终 k 生成完成；Base64 长度 " + finalCiphertext.length());
            }
            if (stopAfter.equals("credentials")) { manifest.put("completed", true); return; }
            // Fetch once per fragment, sequentially for an easy-to-follow experiment.
            for (Pending item : pending) {
                requireFingerprint(fp);
                byte[] bytes = get("lmg", item.url(), bid, false);
                String name = "fragment-" + String.format(Locale.ROOT, "%03d", item.fragment()) + "." + ReaderProtocol.imageExtension(bytes);
                Files.write(output.resolve(name), bytes, StandardOpenOption.CREATE_NEW);
                files.addObject().put("fragmentId", item.fragment()).put("file", name).put("bytes", bytes.length);
                event("lmg", "分片 " + item.fragment() + " 已保存为 " + name);
            }
            manifest.put("completed", true);
        } catch (Exception e) {
            String safe = e instanceof ProtocolException ? e.getMessage() : "处理失败（" + e.getClass().getSimpleName() + "），请检查该步骤的数据格式和会话";
            manifest.put("error", safe);
            event("stopped", safe);
            throw e;
        } finally {
            Json.write(output.resolve("trace.json"), trace);
            Json.write(output.resolve("manifest.json"), manifest);
        }
    }
    @Override public void close() {
        http.dispatcher().executorService().shutdown();
        http.connectionPool().evictAll();
    }
}
