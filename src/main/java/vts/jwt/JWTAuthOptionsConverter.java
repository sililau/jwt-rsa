package vts.jwt;

import vts.jwt.json.JsonArray;
import vts.jwt.json.JsonObject;

public class JWTAuthOptionsConverter {

    public static void fromJson(JsonObject json, JWTAuthOptions obj) {
        if (json.getValue("audience") instanceof JsonArray) {
            java.util.ArrayList<java.lang.String> list = new java.util.ArrayList<>();
            json.getJsonArray("audience").forEach( item -> {
                if (item instanceof String)
                    list.add((String)item);
            });
            obj.setAudience(list);
        }
        if (json.getValue("audiences") instanceof JsonArray) {
            json.getJsonArray("audiences").forEach(item -> {
                if (item instanceof String)
                    obj.addAudience((String)item);
            });
        }
        if (json.getValue("ignoreExpiration") instanceof Boolean) {
            obj.setIgnoreExpiration((Boolean)json.getValue("ignoreExpiration"));
        }
        if (json.getValue("issuer") instanceof String) {
            obj.setIssuer((String)json.getValue("issuer"));
        }
        if (json.getValue("keyStore") instanceof JsonObject) {
            obj.setKeyStore(new KeyStoreOptions((JsonObject)json.getValue("keyStore")));
        }
        if (json.getValue("leeway") instanceof Number) {
            obj.setLeeway(((Number)json.getValue("leeway")).intValue());
        }
        if (json.getValue("permissionsClaimKey") instanceof String) {
            obj.setPermissionsClaimKey((String)json.getValue("permissionsClaimKey"));
        }
        if (json.getValue("pubSecKeys") instanceof JsonArray) {
            json.getJsonArray("pubSecKeys").forEach(item -> {
                if (item instanceof JsonObject)
                    obj.addPubSecKey(new PubSecKeyOptions((JsonObject)item));
            });
        }
        if (json.getValue("secrets") instanceof JsonArray) {
            json.getJsonArray("secrets").forEach(item -> {
                if (item instanceof JsonObject)
                    obj.addSecret(new SecretOptions((JsonObject)item));
            });
        }
    }

    public static void toJson(JWTAuthOptions obj, JsonObject json) {
        if (obj.getAudience() != null) {
            JsonArray array = new JsonArray();
            obj.getAudience().forEach(item -> array.add(item));
            json.put("audience", array);
        }
        json.put("ignoreExpiration", obj.isIgnoreExpiration());
        if (obj.getIssuer() != null) {
            json.put("issuer", obj.getIssuer());
        }
        json.put("leeway", obj.getLeeway());
        if (obj.getPermissionsClaimKey() != null) {
            json.put("permissionsClaimKey", obj.getPermissionsClaimKey());
        }
    }
}