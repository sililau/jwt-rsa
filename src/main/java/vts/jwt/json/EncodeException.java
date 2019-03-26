package vts.jwt.json;

public class EncodeException extends RuntimeException {

    public EncodeException(String message) {
        super(message);
    }

    public EncodeException(String message, Throwable cause) {
        super(message, cause);
    }

    public EncodeException() {
    }
}
