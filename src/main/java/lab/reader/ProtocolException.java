package lab.reader;

import java.io.IOException;

public final class ProtocolException extends IOException {
    private final String stage;
    private final int code;
    public ProtocolException(String stage, int code, String message) {
        super(stage + "：code=" + code + "；" + message);
        this.stage = stage;
        this.code = code;
    }
    public String stage() { return stage; }
    public int code() { return code; }
}
