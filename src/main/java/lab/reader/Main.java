package lab.reader;

import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.HttpUrl;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;

public final class Main {
    public static void main(String[] args) {
        int code;
        try { code = run(args); }
        catch (ProtocolException e) { System.err.println(e.getMessage()); code = 2; }
        catch (IllegalArgumentException e) { System.err.println("参数或数据格式错误：" + e.getMessage()); code = 2; }
        catch (Exception e) {
            // No stack traces or raw parser errors: they may contain captured credentials.
            System.err.println("执行未完成（" + e.getClass().getSimpleName() + "）。检查命令参数、输入文件与该目录的 trace.json。");
            code = 2;
        }
        if (code != 0) System.exit(code);
    }
    static int run(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("help")) {
            System.out.println("""
                Reader Explorer — Java 17+ / OkHttp
                离线验证（不联网）：
                  java -jar reader-explorer.jar verify-har --har FILE --out NEW_DIR
                在线请求单页：
                  java -jar reader-explorer.jar fetch --book ID --page N --session session.json --out NEW_DIR
                    [--volume N] [--stop-after base|preview|credentials|images]
                session.json 参照 session.example.json，使用当前浏览器 Cookie（含 gidf）。
                默认 stop-after=images。输出目录必须为空。日志不包含完整 Cookie、k 或临时凭据。
                """);
            return 0;
        }
        String command = args[0];
        Set<String> valid = switch (command) {
            case "verify-har" -> Set.of("har", "out");
            case "fetch" -> Set.of("book", "page", "session", "out", "volume", "stop-after");
            default -> throw new IllegalArgumentException("未知命令");
        };
        Map<String, String> opts = new HashMap<>();
        for (int i = 1; i < args.length; i += 2) {
            if (i + 1 >= args.length || !args[i].startsWith("--")) throw new IllegalArgumentException("参数需为 --名称 值");
            String key = args[i].substring(2);
            if (!valid.contains(key) || opts.putIfAbsent(key, args[i + 1]) != null) throw new IllegalArgumentException("未知或重复参数");
        }
        Path output = Path.of(require(opts, "out")).toAbsolutePath();
        if (command.equals("verify-har")) {
            Path har = Path.of(require(opts, "har"));
            ObjectNode result = new HarVerifier().verify(har);
            prepareOutput(output);
            Json.write(output.resolve("verification.json"), result);
            System.out.printf("离线验证：once/get %d/%d，lmg %d/%d；单独记录 %d，缺少证据 %d，失败 %d%n",
                result.path("onceVerified").asInt(), result.path("onceSuccessfulCaptured").asInt(),
                result.path("lmgVerified").asInt(), result.path("lmgSuccessfulCaptured").asInt(),
                result.path("observations").size(), result.path("incomplete").size(), result.path("failures").size());
            System.out.println("结果：" + (result.path("passed").asBoolean() ? "通过" : "未通过或证据不足"));
            System.out.println("报告：" + output.resolve("verification.json"));
            return result.path("passed").asBoolean() ? 0 : 1;
        }
        long bid = Long.parseLong(require(opts, "book"));
        int page = Integer.parseInt(require(opts, "page"));
        Integer volume = opts.containsKey("volume") ? Integer.valueOf(opts.get("volume")) : null;
        HttpUrl origin = HttpUrl.get("https://wqbook.wqxuetang.com/");
        BrowserSession session = BrowserSession.load(Path.of(require(opts, "session")), origin);
        prepareOutput(output);
        try (ReaderClient client = new ReaderClient(origin, session, Clock.systemUTC())) {
            client.fetchPage(bid, page, volume, opts.getOrDefault("stop-after", "images"), output);
        }
        System.out.println("结果已保存：" + output);
        return 0;
    }
    private static String require(Map<String, String> options, String name) {
        String value = options.get(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("缺少 --" + name);
        return value;
    }
    private static void prepareOutput(Path directory) throws Exception {
        if (Files.exists(directory)) {
            if (!Files.isDirectory(directory)) throw new IllegalArgumentException("输出路径不是目录");
            try (var files = Files.list(directory)) {
                if (files.findAny().isPresent()) throw new IllegalArgumentException("输出目录必须为空");
            }
        } else Files.createDirectories(directory);
    }
}
