package vts.jwt;

import vts.jwt.json.JsonArray;
import vts.jwt.json.JsonObject;

import java.util.logging.Logger;

public class JWTUser extends AbstractUser {

    private static final Logger log = Logger.getLogger(JWTUser.class.getName());

    private JsonObject jwtToken;
    private JsonArray permissions;

    public JWTUser() {
        // required if the object is serialized, however this is not a good idea
        // because JWT are supposed to be used in stateless environments
        log.info("You are probably serializing the JWT User, JWT are supposed to be used in stateless servers!");
    }

    public JWTUser(JsonObject jwtToken, String permissionsClaimKey) {
        this.jwtToken = jwtToken;

        if(permissionsClaimKey.contains("/")) {
            getNestedJsonValue(jwtToken, permissionsClaimKey);
        } else {
            this.permissions = jwtToken.getJsonArray(permissionsClaimKey, null);
        }

    }
    public void appendToJwtToken(JsonObject encJsonObject){
        this.jwtToken.mergeIn(encJsonObject);
    }

    private void getNestedJsonValue(JsonObject jwtToken, String permissionsClaimKey) {
        String[] keys = permissionsClaimKey.split("/");
        JsonObject obj = null;
        for(int i = 0; i < keys.length; i++) {
            if(i == 0) {
                obj = jwtToken.getJsonObject(keys[i]);
            } else if (i == keys.length -1) {
                if(obj != null) {
                    this.permissions = obj.getJsonArray(keys[i]);
                }
            } else {
                if(obj != null) {
                    obj = obj.getJsonObject(keys[i]);
                }
            }
        }
    }

    @Override
    public JsonObject principal() {
        return jwtToken;
    }

    @Override
    public void setAuthProvider(AuthProvider authProvider) {
        // NOOP - JWT tokens are self contained :)
    }

    @Override
    public boolean doIsPermitted(String permission) {
        if (permissions != null) {
            for (Object jwtPermission : permissions) {
                if (permission.equals(jwtPermission)) {
                    return true;
                }
            }
        }

        log.warning("User has no permission [" + permission + "]");
        return false;
    }


}
