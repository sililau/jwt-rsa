package vts.jwt;

public interface AuthProvider {

    User authenticate(String token) throws JWTokenException;

}
