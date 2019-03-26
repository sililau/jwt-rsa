package vts.jwt;

import vts.jwt.json.JsonObject;

public class JWTKeyStoreOptions {

    // Defaults
    private static final String TYPE = "jceks";

    private String type;
    private String path;
    private String password;

    /**
     * Default constructor
     */
    public JWTKeyStoreOptions() {
        init();
    }

    /**
     * Copy constructor
     *
     * @param other the options to copy
     */
    public JWTKeyStoreOptions(JWTKeyStoreOptions other) {
        type = other.getType();
        path = other.getPath();
        password = other.getPassword();
    }

    private void init() {
        type = TYPE;
    }

    /**
     * Constructor to create an options from JSON
     *
     * @param json the JSON
     */
    public JWTKeyStoreOptions(JsonObject json) {
        init();
        JWTKeyStoreOptionsConverter.fromJson(json, this);
    }

    public String getType() {
        return type;
    }

    public JWTKeyStoreOptions setType(String type) {
        this.type = type;
        return this;
    }

    public String getPath() {
        return path;
    }

    public JWTKeyStoreOptions setPath(String path) {
        this.path = path;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public JWTKeyStoreOptions setPassword(String password) {
        this.password = password;
        return this;
    }
}
