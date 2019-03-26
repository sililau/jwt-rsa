package vts.jwt;

import vts.jwt.json.JsonObject;

public class JWTKeyStoreOptionsConverter {

    public static void fromJson(JsonObject json, JWTKeyStoreOptions obj) {
        if (json.getValue("password") instanceof String) {
            obj.setPassword((String)json.getValue("password"));
        }
        if (json.getValue("path") instanceof String) {
            obj.setPath((String)json.getValue("path"));
        }
        if (json.getValue("type") instanceof String) {
            obj.setType((String)json.getValue("type"));
        }
    }

    public static void toJson(JWTKeyStoreOptions obj, JsonObject json) {
        if (obj.getPassword() != null) {
            json.put("password", obj.getPassword());
        }
        if (obj.getPath() != null) {
            json.put("path", obj.getPath());
        }
        if (obj.getType() != null) {
            json.put("type", obj.getType());
        }
    }
}