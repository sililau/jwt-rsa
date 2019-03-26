package vts.jwt;

import vts.jwt.json.JsonArray;
import vts.jwt.json.JsonObject;

public class PubSecKeyOptionsConverter {

    public static void fromJson(JsonObject json, PubSecKeyOptions obj) {
        if (json.getValue("publicKey") instanceof String) {
            obj.setPublicKey((String)json.getValue("publicKey"));
        }
        if (json.getValue("secretKey") instanceof String) {
            obj.setSecretKey((String)json.getValue("secretKey"));
        }
        if (json.getValue("type") instanceof String) {
            obj.setType((String)json.getValue("type"));
        }
        if (json.getValue("x509Certificates") instanceof JsonArray) {
            json.getJsonArray("x509Certificates").forEach(item -> {
                if (item instanceof String)
                    obj.addX509Certificate((String)item);
            });
        }
    }

    public static void toJson(PubSecKeyOptions obj, JsonObject json) {
        if (obj.getPublicKey() != null) {
            json.put("publicKey", obj.getPublicKey());
        }
        if (obj.getSecretKey() != null) {
            json.put("secretKey", obj.getSecretKey());
        }
        if (obj.getType() != null) {
            json.put("type", obj.getType());
        }
        if (obj.getX509Certificates() != null) {
            JsonArray array = new JsonArray();
            obj.getX509Certificates().forEach(item -> array.add(item));
            json.put("x509Certificates", array);
        }
    }
}