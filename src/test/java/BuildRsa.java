import org.junit.Test;
import vts.jwt.RSAUtil;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static vts.jwt.RSAUtil.writeToFile;

public class BuildRsa {

    /**
     * 生成公钥文件
     * */
    @Test
    public void build() {
        try {
            /*==生成公钥和私钥，公钥传给客户端，私钥保留服务端==*/
            //使用密码创建钥匙
            KeyPair keyPair = RSAUtil.getKeyPair("password");
            // 生成RSA公钥，并Base64编码
            String publicKeyStr = RSAUtil.getPublicKey(keyPair);
            System.out.println(">> RSA public base64 Key:" );
            System.out.println(publicKeyStr);
            //保存公钥文件
            writeToFile("public.key", publicKeyStr);

            //生成Base64的RSA私钥,
            String privateKeyStr = RSAUtil.getPrivateKey(keyPair);
            System.out.println(">> RSA private base64 Key:" );
            System.out.println(privateKeyStr);
            //保存私钥文件
            writeToFile("private.key", privateKeyStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 封装的字符串校验
     * */
    @Test
    public void verificationString() {
        String message = "hello, i am fine, good night!";
        try {
            String publicKeyStr = RSAUtil.readToString("public.key");
            // 根据公钥生成加密内容
            String encryptContext = RSAUtil.encrypt(message, publicKeyStr);
            System.out.println(encryptContext);
            /*==================以下为私钥解密========================*/
            String privateKeyStr = RSAUtil.readToString("private.key");
            String decryptContext = RSAUtil.decrypt(encryptContext, privateKeyStr);
            System.out.println(decryptContext);

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**
     * 校验文件
     * */
    @Test
    public void verification() {
        String message = "hello, i am fine, good night!";
        try {
            String publicKeyStr = RSAUtil.readToString("public.key");
            PublicKey publicKey = RSAUtil.string2PublicKey(publicKeyStr);
            //用公钥加密
            byte[] publicEncrypt = RSAUtil.publicEncrypt(message.getBytes(), publicKey);
            //加密后的内容Base64编码
            String byte2Base64 = RSAUtil.byte2Base64(publicEncrypt);
            System.out.println(">> 公钥加密并Base64编码的结果:");
            System.out.println(byte2Base64);

            System.out.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");


            String privateKeyStr = RSAUtil.readToString("private.key");
            PrivateKey privateKey = RSAUtil.string2PrivateKey(privateKeyStr);
            byte[] base642Byte = RSAUtil.base642Byte(byte2Base64);
            //用私钥解密
            byte[] privateDecrypt = RSAUtil.privateDecrypt(base642Byte, privateKey);
            //解密后的明文
            System.out.println(">> 解密后的明文: ");
            System.out.println(new String(privateDecrypt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
