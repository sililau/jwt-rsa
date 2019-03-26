JSON web token with RSA
项目介绍
一个生成JSON WEB TOKEN 的组件，支持以各种令牌文件生成token
Token主要由三部分组成：
Header（头部）
Payload（负载）
Signature（签名）
其中Payload的内容是base64编码生成，所以一般来说是不存放重要的文件信息，基于一些特殊场景增加了Payload的AES加解密
使用公钥给客户端加密payload内容，由服务端的私钥解密保障了payload的安全性
