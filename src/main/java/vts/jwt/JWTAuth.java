package vts.jwt;

import vts.jwt.json.JsonObject;

public interface JWTAuth extends AuthProvider {

    /**
     * Create a JWT auth provider
     *
     * @param config  the config
     * @return the auth provider
     */
    static JWTAuth create(JsonObject config) {
        return create(new JWTAuthOptions(config));
    }

    /**
     * Create a JWT auth provider
     *
     * @param config  the config
     * @return the auth provider
     */
    static JWTAuth create(JWTAuthOptions config) {
        return new JWTAuthProviderImpl(config);
    }


    /**
     * Generate a new JWT token.
     *
     * @param claims Json with user defined claims for a list of official claims
     *               @see <a href="http://www.iana.org/assignments/jwt/jwt.xhtml">www.iana.org/assignments/jwt/jwt.xhtml</a>
     * @param options extra options for the generation
     *
     * @return JWT encoded token
     */
    String generateToken(JsonObject claims, JWTOptions options);

    /**
     * Generate a new JWT token.
     *
     * @param claims Json with user defined claims for a list of official claims
     *               @see <a href="http://www.iana.org/assignments/jwt/jwt.xhtml">www.iana.org/assignments/jwt/jwt.xhtml</a>
     *
     * @return JWT encoded token
     */
    default String generateToken(JsonObject claims) {
        return generateToken(claims, new JWTOptions());
    }

    void setPublicKey(String publicKeyStr);

    void setPrivateKey(String privateKeyStr);

}
