import org.junit.Test;
import vts.jwt.*;
import vts.jwt.json.JsonObject;

public class SimpleToken {

    /**
     * 生成token参数
     * */
    JWTAuth jwt = JWTAuth.create(new JsonObject()
            .put("keyStore", new JsonObject()
                    .put("type", "jceks")             // 签名文件类型
                    .put("path", "E:\\VTS\\vendor\\JWT\\src\\test\\resources\\keystore.jceks")    // 签名测试文件
                    .put("password", "secret")));

    /***
     * 生成token
     * */
    @Test
    public void build() {
        JsonObject context = new JsonObject();

        context.put("user_id", "UR111111");   // 用户ID
        context.put("name", "张三");          // 名称

        JWTOptions options = new JWTOptions();
        options.addPermission("checked");
    //    options.setExpiresInMinutes(10L);  // 设置失效分钟(分钟/或秒 setExpiresInSeconds)

        long startTime = System.currentTimeMillis();
        // 生成token
        String token = jwt.generateToken(context, options);

        System.out.println(">> BUILD TOKEN:");
        System.out.println(token);
        System.out.println(">> RUNTIME:"+(System.currentTimeMillis() - startTime) + "ms");
    }

    /**
     * 验证token
     * */
    @Test
    public void validation() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiVVIxMTExMTEiLCJuYW1lIjoi5a-u54qx56yBIiwicGVybWlzc2lvbnMiOlsiY2hlY2tlZCJdLCJpYXQiOjE1NTM1MjI4ODl9.qNn4rXW1RB28Gf-65Ah9ZkhKHbYiizO-kK8IYgyn99s";
        long startTime = System.currentTimeMillis();
        try{
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

    @Test
    public void test() {
        // 生成token参数
        JWTAuth jwt = JWTAuth.create(new JsonObject()
                .put("keyStore", new JsonObject()
                        .put("type", "jceks")                                                         // 签名文件类型
                        .put("path", "E:\\VTS\\vendor\\JWT\\src\\test\\resources\\keystore.jceks")    // 签名测试文件
                        .put("password", "secret")));                                                 // 签名文件密码

        // 设置生成token的参数
        JWTOptions options = new JWTOptions();
        // 可增加一个checked权限
        options.addPermission("checked");
        // 增加需要传递的参数
        JsonObject context = new JsonObject().put("user_id", "UR111111");
        // 生成token
        String token = jwt.generateToken(context, options);
        // 计算机校验的开始时间
        long startTime = System.currentTimeMillis();
        try{
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
