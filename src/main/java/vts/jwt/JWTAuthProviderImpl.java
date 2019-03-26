package vts.jwt;

import vts.jwt.json.Json;
import vts.jwt.json.JsonArray;
import vts.jwt.json.JsonObject;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

public class JWTAuthProviderImpl implements JWTAuth {
    private static final JsonArray EMPTY_ARRAY = new JsonArray();

    private final JWT jwt;
    private String publicKey;
    private String privateKey;

    private final String permissionsClaimKey;
    private final String issuer;
    private final List<String> audience;
    private final boolean ignoreExpiration;
    private final int leeway;

    public JWTAuthProviderImpl(JWTAuthOptions config) {
        this.permissionsClaimKey = config.getPermissionsClaimKey();
        this.issuer = config.getIssuer();
        this.audience = config.getAudience();
        this.ignoreExpiration = config.isIgnoreExpiration();
        this.leeway = config.getLeeway();

        final KeyStoreOptions keyStore = config.getKeyStore();

        // attempt to load a Key file
        try {
            if (keyStore != null) {
                KeyStore ks = KeyStore.getInstance(keyStore.getType());

                // synchronize on the class to avoid the case where multiple file accesses will overlap
                synchronized (JWTAuthProviderImpl.class) {
                    try ( InputStream in = new FileInputStream(keyStore.getPath())) {
                        ks.load(in, keyStore.getPassword().toCharArray());
                    }
                }

                this.jwt = new JWT(ks, keyStore.getPassword().toCharArray());
            } else {
                // no key file attempt to load pem keys
                this.jwt = new JWT();

                final List<PubSecKeyOptions> keys = config.getPubSecKeys();

                if (keys != null) {
                    for (PubSecKeyOptions key : keys) {
                        this.jwt.addKeyPair(key.getType(), key.getPublicKey(), key.getSecretKey());
                    }
                }

                final List<SecretOptions> secrets = config.getSecrets();

                if (secrets != null) {
                    for (SecretOptions secret: secrets) {
                        this.jwt.addSecret(secret.getType(), secret.getSecret());
                    }
                }
            }

        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public void setPublicKey(String publicKeyStr) {
        try{
            this.publicKey = publicKeyStr;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void setPrivateKey(String privateKeyStr) {
        try{
            this.privateKey = privateKeyStr;
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public User authenticate(String token) throws JWTokenException {
        final JsonObject payload = jwt.decode(token);

        // All dates in JWT are of type NumericDate
        // a NumericDate is: numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until
        // the specified UTC date/time, ignoring leap seconds
        final long now = (System.currentTimeMillis() / 1000);
        if (payload.containsKey("exp") && !ignoreExpiration) {
            if (now - leeway >= payload.getLong("exp")) {
                throw new JWTokenException("Expired JWT token: exp <= now");
            }
        }
        if (payload.containsKey("iat")) {
            Long iat = payload.getLong("iat");
            // issue at must be in the past
            if (iat > now + leeway) {
                throw new JWTokenException("Invalid JWT token: iat > now");
            }
        }

        if (payload.containsKey("nbf")) {
            Long nbf = payload.getLong("nbf");
            // not before must be after now
            if (nbf > now + leeway) {
                throw new JWTokenException("Invalid JWT token: nbf > now");
            }
        }

        if (audience != null) {
            JsonArray target;
            if (payload.getValue("aud") instanceof String) {
                target = new JsonArray().add(payload.getValue("aud", ""));
            } else {
                target = payload.getJsonArray("aud", EMPTY_ARRAY);
            }

            if (Collections.disjoint(audience, target.getList())) {
                throw new JWTokenException("Invalid JWT audient. expected: " + Json.encode(audience));
            }
        }

        if (issuer != null) {
            if (!issuer.equals(payload.getString("iss"))) {
                throw new JWTokenException("Invalid JWT issuer");
            }
        }
        JWTUser jWTUser = new JWTUser(payload, permissionsClaimKey);
        if (this.privateKey != null) {
            JsonObject principal = jWTUser.principal();
            if (principal.containsKey("enc")) {
                try {
                    JsonObject encJsonObject = new JsonObject(RSAUtil.decrypt(principal.getString("enc"), this.privateKey));
                    principal.remove("enc");
                    jWTUser.appendToJwtToken(encJsonObject);
                } catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
        return jWTUser;

    }

    @Override
    public String generateToken(JsonObject claims, final JWTOptions options) {
        final JsonObject jsonOptions = options.toJson();
        JsonObject _claims;
        if (publicKey != null) {
            try {
                _claims = new JsonObject().put("enc", RSAUtil.encrypt(claims.copy().toString(), this.publicKey));
            } catch (Exception e) {
                e.printStackTrace();
                _claims = claims.copy();
            }
        } else {
            _claims = claims.copy();
        }
        // we do some "enhancement" of the claims to support roles and permissions
        if (jsonOptions.containsKey("permissions") && !_claims.containsKey(permissionsClaimKey)) {
            _claims.put(permissionsClaimKey, jsonOptions.getJsonArray("permissions"));
        }
        return jwt.sign(_claims, jsonOptions);
    }

    static JWTAuth create(JsonObject config) {
        return new JWTAuthProviderImpl(new JWTAuthOptions(config));
    }

}