# JSON web token with RSA
## 项目介绍 <br/>
一个生成JSON WEB TOKEN 的组件，支持以各种令牌文件生成token<br/>
Token主要由三部分组成： <br/>
Header（头部） <br/>
Payload（负载） <br/>
Signature（签名）<br/>
其中Payload的内容是base64编码生成，所以一般来说是不存放重要的文件信息，基于一些特殊场景增加了Payload的AES加解密
使用公钥给客户端加密payload内容，由服务端的私钥解密保障了payload的安全性
****
# 引入
### MAVEN <br />
```
<dependency>
  <groupId>com.kavi</groupId>
  <artifactId>jwt-rsa</artifactId>
  <version>1.0.1</version>
  <type>pom</type>
</dependency>
```
### gradle
compile 'com.kavi:jwt-rsa:1.0.1'

# 使用
```
        JWTAuth jwt = JWTAuth.create(new JsonObject()
                .put("keyStore", new JsonObject()
                        .put("type", "jceks")               // 签名文件类型
                        .put("path", "\\keystore.jceks")    // 签名测试文件
                        .put("password", "secret")));       // 签名文件密码

        // 设置生成token的参数
        JWTOptions options = new JWTOptions();
        // 可增加一个checked权限
        options.addPermission("checked");
        // 增加需要传递的参数
        JsonObject context = new JsonObject().put("user_id", "123456");
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
```

<br/>
说明：代码基于Vertx的 vertx-jwt参考及引用，只是在原有基础上略作封装和脱离了vertx的环境以便在其他java环境应用
