package vts.jwt;

import java.util.HashSet;
import java.util.Set;

public abstract class AbstractUser implements User {

    protected final Set<String> cachedPermissions = new HashSet<>();

    @Override
    public boolean isAuthorised(String authority) {
        if (cachedPermissions.contains(authority)) {
            return true;
        } else {
            boolean isPermitted = doIsPermitted(authority);
            if (isPermitted) cachedPermissions.add(authority);
            return isPermitted;
        }
    }

    @Override
    public User clearCache() {
        cachedPermissions.clear();
        return this;
    }

    protected abstract boolean doIsPermitted(String permission);

}
