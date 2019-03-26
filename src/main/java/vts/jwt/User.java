package vts.jwt;

import vts.jwt.json.JsonObject;

public interface User {

    /**
     * Is the user authorised to
     *
     * @param authority  the authority - what this really means is determined by the specific implementation. It might
     *                   represent a permission to access a resource e.g. `printers:printer34` or it might represent
     *                   authority to a role in a roles based model, e.g. `role:admin`.
     *                       `true` if the they has the authority or `false` otherwise.
     * @return the User to enable fluent use
     */
    boolean isAuthorised(String authority);

    /**
     * The User object will cache any authorities that it knows it has to avoid hitting the
     * underlying auth provider each time.  Use this method if you want to clear this cache.
     *
     * @return the User to enable fluent use
     */
    User clearCache();

    /**
     * Get the underlying principal for the User. What this actually returns depends on the implementation.
     * For a simple user/password based auth, it's likely to contain a JSON object with the following structure:
     * <pre>
     *   {
     *     "username", "tim"
     *   }
     * </pre>
     * @return JSON representation of the Principal
     */
    JsonObject principal();

    /**
     * Set the auth provider for the User. This is typically used to reattach a detached User with an AuthProvider, e.g.
     * after it has been deserialized.
     *
     * @param authProvider  the AuthProvider - this must be the same type of AuthProvider that originally created the User
     */
    void setAuthProvider(AuthProvider authProvider);
}
