package vts.jwt;

import vts.jwt.json.JsonObject;

import java.util.ArrayList;
import java.util.List;

public class JWTAuthOptions {

    // Defaults
    private static final String PERMISSIONS_CLAIM_KEY = "permissions";
    private static final boolean IGNORE_EXPIRATION = false;
    private static final int LEEWAY = 0;


    private String permissionsClaimKey;
    private KeyStoreOptions keyStore;
    private List<PubSecKeyOptions> pubSecKeys;
    private List<SecretOptions> secrets;
    private List<String> audience;
    private String issuer;
    private boolean ignoreExpiration;
    private int leeway;

    /**
     * Default constructor
     */
    public JWTAuthOptions() {
        init();
    }

    /**
     * Copy constructor
     *
     * @param other the options to copy
     */
    public JWTAuthOptions(JWTAuthOptions other) {
        permissionsClaimKey = other.getPermissionsClaimKey();
        keyStore = other.getKeyStore();
        pubSecKeys = other.getPubSecKeys();
        secrets = other.getSecrets();
        audience = other.getAudience();
        issuer = other.getIssuer();
        ignoreExpiration = other.isIgnoreExpiration();
        leeway = other.getLeeway();
    }

    private void init() {
        permissionsClaimKey = PERMISSIONS_CLAIM_KEY;
        ignoreExpiration = IGNORE_EXPIRATION;
        leeway = LEEWAY;
    }

    /**
     * Constructor to create an options from JSON
     *
     * @param json the JSON
     */
    public JWTAuthOptions(JsonObject json) {
        init();
        JWTAuthOptionsConverter.fromJson(json, this);
    }


    public String getPermissionsClaimKey() {
        return permissionsClaimKey;
    }

    public JWTAuthOptions setPermissionsClaimKey(String permissionsClaimKey) {
        this.permissionsClaimKey = permissionsClaimKey;
        return this;
    }

    public KeyStoreOptions getKeyStore() {
        return keyStore;
    }

    public JWTAuthOptions setKeyStore(KeyStoreOptions keyStore) {
        this.keyStore = keyStore;
        return this;
    }

    public List<PubSecKeyOptions> getPubSecKeys() {
        return pubSecKeys;
    }

    public JWTAuthOptions setPubSecKeys(List<PubSecKeyOptions> pubSecKeys) {
        this.pubSecKeys = pubSecKeys;
        return this;
    }

    public List<SecretOptions> getSecrets() {
        return secrets;
    }

    public void setSecrets(List<SecretOptions> secrets) {
        this.secrets = secrets;
    }

    public JWTAuthOptions addSecret(SecretOptions secret) {
        if (this.secrets == null) {
            this.secrets = new ArrayList<>();
        }
        this.secrets.add(secret);
        return this;
    }

    public JWTAuthOptions addPubSecKey(PubSecKeyOptions pubSecKey) {
        if (this.pubSecKeys == null) {
            this.pubSecKeys = new ArrayList<>();
        }
        this.pubSecKeys.add(pubSecKey);
        return this;
    }

    public List<String> getAudience() {
        return audience;
    }

    /**
     * Set the audience list
     * @param audience  the audience list
     * @return a reference to this for fluency
     */
    public JWTAuthOptions setAudience(List<String> audience) {
        this.audience = audience;
        return this;
    }

    /**
     * Set the audience list
     * @param audience  the audience list
     * @return a reference to this for fluency
     */
    public JWTAuthOptions addAudience(String audience) {
        if (this.audience == null) {
            this.audience = new ArrayList<>();
        }
        this.audience.add(audience);
        return this;
    }

    public String getIssuer() {
        return issuer;
    }

    /**
     * Set the issuer
     * @param issuer  the issuer
     * @return a reference to this for fluency
     */
    public JWTAuthOptions setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public boolean isIgnoreExpiration() {
        return ignoreExpiration;
    }

    /**
     * Set whether expiration is ignored
     * @param ignoreExpiration  whether expiration is ignored
     * @return a reference to this for fluency
     */
    public JWTAuthOptions setIgnoreExpiration(boolean ignoreExpiration) {
        this.ignoreExpiration = ignoreExpiration;
        return this;
    }

    public int getLeeway() {
        return leeway;
    }

    /**
     * Set the leeway in seconds
     * @param leeway  in seconds
     * @return a reference to this for fluency
     */
    public JWTAuthOptions setLeeway(int leeway) {
        this.leeway = leeway;
        return this;
    }
}
