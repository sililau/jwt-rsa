package vts.jwt;

import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.X500Name;

import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class KeyStoreBuilder {

    /**
     * @param file 存储路径
     * @param password 密码
     * 默认有效期一年
     * 默认使用 JCEKS
     * 默认 RSA算法
     * */
    public static Map<String, String> build(
            String file,
            String password
    ) throws Exception {
        return build(
                file,
                password,
                (long)86400 * 365 * 1000,
                "RS256",
                "JCEKS",
                "RSA",
                "SHA256withRSA",
                1024,
                null,"", "","","","","china");
    }

    /**
     * @param file 存储路径
     * @param password 密码
     * @param validity 有效期
     * @param alias 算法别名 RS256 / HS256 / HS384 / HS512 / RS384 / RS512 / ES256 / ES384 / ES512
     * @param type 存储类型  JKS/ JCEKS / PKCS12
     * @param keyAlg 算法
     *               SHA1withDSA   如果生成KeyPair使用的时DS
     *               SHA256withRSA 如果生成KeyPair使用的时RSA算法
     *               SHA256withECDSA 如果生成KeyPair使用的时EC算法
     * @param sigAlg 签名
     *               SHA1withDSA / SHA256withRSA / SHA256withECDSA
     * @param keySize 长度 默认 1024
     * @param ksPwd store 密码
     * @param cn 个人常用名
     * @param ou 组织或部门
     * @param o 集团或机构
     * @param city 城市
     * @param state 区域
     * @param country 国家
     * */
    public static Map<String, String> build(
            String file,
            String password,
            Long validity,
            String alias,
            String type,
            String keyAlg,
            String sigAlg,
            int keySize,
            String ksPwd,
            String cn,
            String ou,
            String o,
            String city,
            String state,
            String country
    ) throws Exception {
        KeyStore ks = KeyStore.getInstance(type);
        ks.load(null, ksPwd != null ? ksPwd.toCharArray() :  null);
        CertAndKeyGen keyPair = new CertAndKeyGen(keyAlg, sigAlg, null);
        X500Name x500Name = new X500Name(cn, ou, o, city, state, country);
        keyPair.generate(keySize);

        PrivateKey privateKey = keyPair.getPrivateKey();
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = keyPair.getSelfCertificate(x500Name, new Date(), validity);
        char[] keyPassword = password.toCharArray();
        // store away the key store
        FileOutputStream fos = new FileOutputStream(file);
        ks.setKeyEntry(alias, privateKey, keyPassword, chain);
        ks.store(fos, keyPassword);
        fos.close();

        return new HashMap<String, String>(){{
            put("file",file);
            put("password", password);
            put("validity", validity.toString());
            put("alias", alias);
            put("type", type);
            put("keyAlg", keyAlg);
            put("sigAlg", sigAlg);
            put("keySize", ""+keySize+"");
            put("CommonName ", cn);
            put("OrganizationUnit ", ou);
            put("OrganizationName ", o);
            put("city ", city);
            put("state ", state);
            put("country ",country);
        }};
    }
}
