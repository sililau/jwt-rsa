import org.junit.Test;
import vts.jwt.*;
import vts.jwt.json.JsonObject;

public class AesToken {

    @Test
    public void buildKeyStore() {
        try {
            KeyStoreBuilder.build("test.jceks", "123456");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /***
     * 生成token，基于公钥的内容加密
     * */
    @Test
    public void build() {
        try {
            String publicKeyStr = RSAUtil.readToString("public.key");
            JWTAuth jwt = JWTAuth.create(new JsonObject()
                    .put("keyStore", new JsonObject()
                            .put("type", "JCEKS")             // 签名文件类型
                            .put("path", "E:\\KAVI\\jwt-rsa\\test.jceks")    // 签名测试文件
                            .put("password", "123456")));
        //    jwt.setPublicKey(publicKeyStr);

            JsonObject context = new JsonObject();

            context.put("user_id", "UR111111");   // 用户ID
            context.put("name", "张三");          // 名称

            JWTOptions options = new JWTOptions();
            options.addPermission("checked");
         //   options.setExpiresInMinutes(10L);  // 设置失效分钟(分钟/或秒 setExpiresInSeconds)

            long startTime = System.currentTimeMillis();
            // 生成token
            String token = jwt.generateToken(context, options);

            System.out.println(">> BUILD TOKEN:");
            System.out.println(token);
            System.out.println(">> RUNTIME:"+(System.currentTimeMillis() - startTime) + "ms");
        } catch (Exception e){
             e.printStackTrace();
        }
    }

    /**
     * 验证token
     * */
    @Test
    public void validation() {

        String token ="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJlbmMiOiJYMmp1NFZVT0txcjZMaE9Xb1VmYStRdWtZZXhUU045MGFRMmdlaEJTODNIYk5YNU5uZGRON3JCN2ZncDArM0U1MjFxS1I5dk0xR1FUXHJcblBWL2pGRFVzZk5hUzZTUXFTR3JoVjZQU0pHM0V2V0NUVDJ4cVlINVV0QVlkalMzL01oREdhK2poSFlyUDhEMEMwd3VNSzVCdytFaXBcclxuczg4ZlZSUjg3ejFYRzJUN1l1K1BmTkdZMlcyYjh2bmcwbFFDbHltQWs4VWloeEx0MW9vaEJXaXkvZmdtTVFiR3dsUUxGSlB5REhEZ1xyXG53TzAyZEdheW5DMmxyelFBeHhaYTM4bTNGOTk3WmxSNHdQT0p6NFBWZkZnejFqMEQxVVFHOUg2TVZNeUZKbm5vbDF1ZnpnM2k2ejk4XHJcblZ4NkVXSFhFMm1zZTVJTmJYNlVQWm9EWGZKRlJYQms3QlJRSXhnPT0iLCJwZXJtaXNzaW9ucyI6WyJjaGVja2VkIl0sImlhdCI6MTU1MzUyMjM5NH0.RHCJ4Hp3M4etCYOi51cskv1hI8XByx7OUD36SOmufMA";
        long startTime = System.currentTimeMillis();
        try{
            JWTAuth jwt = JWTAuth.create(new JsonObject()
                    .put("keyStore", new JsonObject()
                            .put("type", "jceks")             // 签名文件类型
                            .put("path", "E:\\VTS\\vendor\\JWT\\src\\main\\resources\\keystore.jceks")    // 签名测试文件
                            .put("password", "secret")));

            // 设置私钥
            String privateKeyStr = RSAUtil.readToString("private.key");
            jwt.setPrivateKey(privateKeyStr);
            // 验证token
            User user = jwt.authenticate(token);
            System.out.println(">> TOKEN RESULT:");
            //获取token的JSON内容参数
            System.out.println(user.principal());
            // 验证token是否拥有某个权限
            if (user.isAuthorised("checked")) {
                System.out.println(">> Has Permission: Checked");
            }
        } catch (Exception e){
            e.printStackTrace();
        }
        System.out.println(">> RUNTIME: "+(System.currentTimeMillis() - startTime) + "ms");
    }
}
