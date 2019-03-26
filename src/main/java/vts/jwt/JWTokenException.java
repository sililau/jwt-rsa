package vts.jwt;

public class JWTokenException extends RuntimeException {

    public JWTokenException() {
    }

    public JWTokenException(String message) {
        super(message);
    }

    public JWTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
