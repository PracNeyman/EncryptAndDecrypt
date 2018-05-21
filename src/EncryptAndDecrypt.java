import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.Base64;

public class EncryptAndDecrypt {

    public static void jdkRSA() {
        try {
            String src = "Hello RSA!";
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
            System.out.println("公钥为");
            System.out.println(Base64.encodeBase64String(rsaPublicKey.getEncoded()));
            System.out.println("私钥为");
            System.out.println(Base64.encodeBase64String(rsaPrivateKey.getEncoded()));

            //私钥加密，公钥解密——加密
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            Cipher cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] result = cipher.doFinal(src.getBytes());
            System.out.println("RSA私钥加密，公钥解密--加密:"+Base64.encodeBase64String(result));

            //私钥加密，公钥解密--解密
            X509EncodedKeySpec x509EncodedKeySpec=new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            PublicKey publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,publicKey);
            result = cipher.doFinal(result);
            System.out.println("RSA私钥加密，公钥解密--解密:"+new String(result));


            //公钥加密，私钥解密--加密
            x509EncodedKeySpec=new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            publicKey=keyFactory.generatePublic(x509EncodedKeySpec);
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            result = cipher.doFinal(src.getBytes());
            System.out.println("RSA公钥加密，私钥解密--加密:"+Base64.encodeBase64String(result));

            //公钥加密，私钥解密--解密
            pkcs8EncodedKeySpec=new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            keyFactory=KeyFactory.getInstance("RSA");
            privateKey =keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            cipher=Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            result=cipher.doFinal(result);
            System.out.println("RSA公钥加密，私钥解密--解密:"+new String(result));

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }

    }


    public static void jdkDES(){
        try {
            String src = "Hello DES!";
            //生成key
            KeyGenerator keyGenerator=KeyGenerator.getInstance("DES");
            keyGenerator.init(56);      //指定key长度，同时也是密钥长度(56位)
            SecretKey secretKey = keyGenerator.generateKey(); //生成key的材料
            byte[] key = secretKey.getEncoded();  //生成key

            //key转换成密钥
            DESKeySpec desKeySpec=new DESKeySpec(key);
            SecretKeyFactory factory=SecretKeyFactory.getInstance("DES");
            SecretKey key2 = factory.generateSecret(desKeySpec);      //转换后的密钥

            //加密
            Cipher cipher=Cipher.getInstance("DES/ECB/PKCS5Padding");  //算法类型/工作方式/填充方式
            cipher.init(Cipher.ENCRYPT_MODE, key2);   //指定为加密模式
            byte[] result=cipher.doFinal(src.getBytes());
            System.out.println("jdkDES加密: "+Hex.encodeHexString(result));  //转换为十六进制

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key2);  //相同密钥，指定为解密模式
            result = cipher.doFinal(result);   //根据加密内容解密
            System.out.println("jdkDES解密: "+new String(result));  //转换字符串

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void jdk3DES(){
        try {
            String src = "Hello 3DES!";
            //生成key
            KeyGenerator keyGenerator=KeyGenerator.getInstance("DESede");
            //keyGenerator.init(112);      //3DES需要112 or 168位
            keyGenerator.init(new SecureRandom());   //或者使用这种方式默认长度，无需指定长度
            SecretKey secretKey = keyGenerator.generateKey(); //生成key的材料
            byte[] key = secretKey.getEncoded();  //生成key

            //key转换成密钥
            DESedeKeySpec desKeySpec=new DESedeKeySpec(key);
            SecretKeyFactory factory=SecretKeyFactory.getInstance("DESede");
            SecretKey key2 = factory.generateSecret(desKeySpec);      //转换后的密钥

            //加密
            Cipher cipher=Cipher.getInstance("DESede/ECB/PKCS5Padding");  //算法类型/工作方式/填充方式
            cipher.init(Cipher.ENCRYPT_MODE, key2);   //指定为加密模式
            byte[] result=cipher.doFinal(src.getBytes());
            System.out.println("jdk3DES加密: "+Hex.encodeHexString(result));  //转换为十六进制

            //解密
            cipher.init(Cipher.DECRYPT_MODE,key2);  //相同密钥，指定为解密模式
            result = cipher.doFinal(result);   //根据加密内容解密
            System.out.println("jdk3DES解密: "+new String(result));  //转换字符串

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args){
        jdkRSA();
        jdkDES();
        jdk3DES();
    }
}
