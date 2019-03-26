package vts.jwt;

import vts.jwt.json.JsonObject;

public class SecretOptionsConverter {

    public static void fromJson(JsonObject json, SecretOptions obj) {
        if (json.getValue("secret") instanceof String) {
            obj.setSecret((String)json.getValue("secret"));
        }
        if (json.getValue("type") instanceof String) {
            obj.setType((String)json.getValue("type"));
        }
    }

    public static void toJson(SecretOptions obj, JsonObject json) {
        if (obj.getSecret() != null) {
            json.put("secret", obj.getSecret());
        }
        if (obj.getType() != null) {
            json.put("type", obj.getType());
        }
    }
}