package lab.reader;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.HttpUrl;
import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import static java.nio.charset.StandardCharsets.UTF_8;

/** Captured reader version 8.0.422. No browser hooks, WASM runtime, or network calls. */
public final class ReaderProtocol {
    public record Preview(byte[] image, String extension, String salt,
                          List<Integer> fragments, List<String> geometry, int metadataBytes) {}

    public String encrypt(String plaintext, String fingerprint) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(crypt(plaintext.getBytes(UTF_8), fingerprint, 1));
    }
    public String decrypt(String base64, String fingerprint, int counter) throws GeneralSecurityException {
        return new String(crypt(Base64.getDecoder().decode(base64), fingerprint, counter), UTF_8);
    }
    private byte[] crypt(byte[] input, String fingerprint, int counter) throws GeneralSecurityException {
        if (fingerprint == null || fingerprint.isBlank()) throw new IllegalArgumentException("缺少 gidf 浏览器指纹");
        byte[] fp = fingerprint.getBytes(UTF_8), seed = "shenduronghe".getBytes(UTF_8);
        byte[] nonceSeed = "deep".getBytes(UTF_8), key = new byte[32], nonce = new byte[12];
        for (int i = 0; i < key.length; i++) key[i] = (byte)(seed[i % seed.length] ^ fp[i % fp.length]);
        for (int i = 0; i < nonce.length; i++) nonce[i] = (byte)(nonceSeed[i % nonceSeed.length] ^ fp[i % fp.length]);
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"),
            new ChaCha20ParameterSpec(nonce, counter));
        return cipher.doFinal(input);
    }
    public String smallKey(ObjectNode baseCredential) {
        String json = Json.compact(baseCredential);
        for (int i = 0; i < json.length(); i++)
            if (json.charAt(i) > 255) throw new IllegalArgumentException("基础凭据不符合浏览器 btoa 的单字节输入要求");
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.ISO_8859_1));
    }
    public ObjectNode oncePayload(long bid, String page, long timestamp, ObjectNode base, int fragment) {
        ObjectNode payload = payload(bid, page, timestamp, Json.compact(base));
        payload.put("zn", fragment);
        return payload;
    }
    public ObjectNode finalPayload(long bid, String page, long timestamp, ObjectNode temporary) {
        return payload(bid, page, timestamp, Json.compact(temporary));
    }
    private ObjectNode payload(long bid, String page, long timestamp, String credential) {
        // JSON.stringify insertion order and string page number are part of the byte representation.
        ObjectNode result = Json.MAPPER.createObjectNode();
        result.put("p", page).put("t", timestamp).put("b", bid).put("w", 1000).put("k", credential);
        return result;
    }
    public ObjectNode decryptTemporary(String ciphertext, ObjectNode base)
            throws GeneralSecurityException, IOException {
        String i = base.path("i").asText("");
        if (i.isEmpty()) throw new IOException("基础凭据缺少 i");
        String keyText = (i.substring(0, Math.min(16, i.length())) + "0000000000000000").substring(0, 16);
        byte[] key = keyText.getBytes(UTF_8);
        if (key.length != 16) throw new IOException("该版本要求 AES key 的 UTF-8 长度为 16 字节");
        byte[] data = Base64.getDecoder().decode(ciphertext);
        // CryptoJS's OpenSSL formatter may prefix Salted__ + an 8-byte salt; the explicit raw key is retained.
        if (data.length >= 16 && new String(data, 0, 8, StandardCharsets.US_ASCII).equals("Salted__"))
            data = Arrays.copyOfRange(data, 16, data.length);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // AES block size gives PKCS#7 semantics.
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
        return Json.object(Json.parse(new String(cipher.doFinal(data), UTF_8)), "临时凭据");
    }
    public ObjectNode finishTemporary(ObjectNode original, String salt, String frameUrl)
            throws GeneralSecurityException {
        ObjectNode result = original.deepCopy();
        result.put("w", frameUrl == null ? "" : frameUrl);
        List<String> names = new ArrayList<>();
        result.fieldNames().forEachRemaining(names::add);
        Collections.sort(names);
        // Source takes the key list BEFORE removing a falsy zn.
        if (!truthy(result.get("zn"))) result.remove("zn");
        StringBuilder text = new StringBuilder();
        for (String name : names) text.append(jsString(result.get(name))).append(salt);
        result.put("xx", HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(text.toString().getBytes(UTF_8))));
        return result;
    }
    private static boolean truthy(JsonNode node) {
        if (node == null || node.isNull()) return false;
        if (node.isBoolean()) return node.booleanValue();
        if (node.isNumber()) return node.doubleValue() != 0;
        return !node.isTextual() || !node.textValue().isEmpty();
    }
    private static String jsString(JsonNode node) {
        if (node == null) return "undefined";
        if (node.isNull()) return "null";
        if (node.isTextual()) return node.textValue();
        if (node.isNumber() || node.isBoolean()) return node.asText();
        throw new IllegalArgumentException("不支持的临时凭据字段类型，停止以免生成错误校验值");
    }
    public Preview parsePreview(byte[] bytes, String fingerprint, int pageIndex)
            throws IOException, GeneralSecurityException {
        if (bytes.length < 10) throw new IOException("预览响应过短");
        long length = Integer.toUnsignedLong(ByteBuffer.wrap(bytes, bytes.length - 4, 4).getInt());
        if (length < 1 || length > bytes.length - 10L) throw new IOException("预览元数据长度不合法");
        int start = bytes.length - 4 - (int)length;
        int status = ((bytes[start - 6] & 255) << 8) | (bytes[start - 5] & 255);
        String raw = new String(bytes, start, (int)length, StandardCharsets.ISO_8859_1);
        if (status != 0 || raw.equals("0000000000"))
            throw new ProtocolException("imgs", status, "预览业务状态失败；未继续申请分片");
        String clear = raw.contains("[") && raw.contains("]") ? raw : decrypt(raw, fingerprint, pageIndex);
        int left = clear.lastIndexOf('['), right = clear.lastIndexOf(']');
        if (left < 1 || right < left || right + 1 >= clear.length())
            throw new IOException("预览元数据结构与已验证版本不一致");
        JsonNode parts = Json.parse(clear.substring(left, right + 1));
        if (parts == null || !parts.isArray() || parts.isEmpty() || parts.size() > 128)
            throw new IOException("分片数组无效或过大");
        List<Integer> fragments = new ArrayList<>();
        for (JsonNode part : parts) {
            if (!part.isIntegralNumber() || !part.canConvertToInt()) throw new IOException("分片编号必须为整数");
            int n = part.intValue();
            if (n < 0 || n >= parts.size() || fragments.contains(n)) throw new IOException("分片编号不是完整排列");
            fragments.add(n);
        }
        byte[] image = Arrays.copyOf(bytes, start - 6);
        return new Preview(image, imageExtension(image), clear.substring(0, left - 1),
            List.copyOf(fragments), List.of(clear.substring(right + 2).split("-")), (int)length);
    }
    public static String imageExtension(byte[] data) throws IOException {
        if (data.length >= 12 && new String(data, 0, 4, StandardCharsets.US_ASCII).equals("RIFF")
                && new String(data, 8, 4, StandardCharsets.US_ASCII).equals("WEBP")) return "webp";
        if (data.length >= 3 && (data[0] & 255) == 255 && (data[1] & 255) == 216 && (data[2] & 255) == 255) return "jpg";
        if (data.length >= 8 && Arrays.equals(Arrays.copyOf(data, 8),
                new byte[]{(byte)137,80,78,71,13,10,26,10})) return "png";
        throw new IOException("响应不是已识别的 WebP/JPEG/PNG 图像");
    }
    /** JavaScript encodeURIComponent, not application/x-www-form-urlencoded. */
    public static String encodeUri(String value) {
        StringBuilder result = new StringBuilder();
        String safe = "-_.!~*'()";
        for (byte v : value.getBytes(UTF_8)) {
            int b = v & 255;
            if (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || safe.indexOf(b) >= 0)
                result.append((char)b);
            else result.append('%').append("0123456789ABCDEF".charAt(b >>> 4)).append("0123456789ABCDEF".charAt(b & 15));
        }
        return result.toString();
    }
    public static String decodeUri(String value) {
        return URLDecoder.decode(value.replace("+", "%2B"), UTF_8);
    }
    public static HttpUrl onceUrl(HttpUrl base, long bid, String page, String ciphertext) {
        // encryptText returns Base64; application encoding then OkHttp query serialization = TWO layers.
        return base.newBuilder().encodedPath("/deep/page/once/get").query(null)
            .addQueryParameter("bid", Long.toString(bid)).addQueryParameter("pnum", page)
            .addQueryParameter("k", encodeUri(ciphertext)).build();
    }
    public static HttpUrl imageUrl(HttpUrl base, long bid, String page, Integer volume, String ciphertext) {
        HttpUrl.Builder b = base.newBuilder().encodedPath("/deep/page/lmg/" + bid + "/" + page).query(null);
        if (volume != null) b.addQueryParameter("v", volume.toString());
        return b.addEncodedQueryParameter("k", encodeUri(ciphertext)).build();
    }
}
