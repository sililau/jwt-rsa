package vts.jwt;

import vts.jwt.json.JsonObject;

public class KeyStoreOptions {

    // Defaults
    private static final String TYPE = "jceks";

    private String type;
    private String path;
    private String password;

    /**
     * Default constructor
     */
    public KeyStoreOptions() {
        init();
    }

    /**
     * Copy constructor
     *
     * @param other the options to copy
     */
    public KeyStoreOptions(KeyStoreOptions other) {
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
    public KeyStoreOptions(JsonObject json) {
        init();
        KeyStoreOptionsConverter.fromJson(json, this);
    }

    public String getType() {
        return type;
    }

    public KeyStoreOptions setType(String type) {
        this.type = type;
        return this;
    }

    public String getPath() {
        return path;
    }

    public KeyStoreOptions setPath(String path) {
        this.path = path;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public KeyStoreOptions setPassword(String password) {
        this.password = password;
        return this;
    }
}
