package dk.obeid;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Random;

import static dk.obeid.User.AES.encryptPassword;

public class User {
    private String username = null;
    private byte[] encryptedPassword = null,  salt = new byte[16];

    /**
     *
     * @param u
     * @param p
     */
    public User(String u, String p){
        salt = initialisationVector();
        encryptedPassword = encryptPassword(p, salt);
        username = u;
    }

    /**
     * modified from stackoverflow.com/questions/18268502/how-to-generate-salt-value-in-java
     * to generate a crypto-random salt
     * @return salt
     */
    private byte[] initialisationVector(){
        final Random r = new SecureRandom();
        byte[] ivBytes = new byte[16];
        r.nextBytes(ivBytes);
        return ivBytes;
    }

    /**
     *
     * @return
     */
    public byte[] getEncryptedPassword() {
        return encryptedPassword;
    }

    /**
     *
     * @return
     */
    public String getUsername() {
        return username;
    }

    /**
     *
     * @return
     */
    public byte[] getSalt() {
        return salt;
    }


    /**
     * modified from https://gist.github.com/bricef/2436364
     */
    protected static class AES {
        /**
         * hardcoded key, so we have the same encrypted password versions
         * even if the server is rebooted or something.
         */
        private static final String key = "aL30f-39g(24OfD?";
        /**
         * AES key size
         */
        private static final int AES_Key_Size = 256;

        /**
         *
         * @param password
         * @param salt
         * @return password encrypted
         */
        protected static byte[] encryptPassword(String password, byte[] salt) {
            byte[] encryptedPassword = null;
            try {
                encryptedPassword = encrypt(password, key, salt);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return encryptedPassword;
        }

        /**
         *
         * @param data
         * @param secretKey
         * @return data encrypted
         */
        protected static byte[] encryptData(String data, SecretKey secretKey){
            byte[] encrypted = null;
            try {
                encrypted = encrypt(data, secretKey);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return encrypted;
        }

        /**
         *
         * @param plain
         * @param key
         * @param salt
         * @return password encrypted with a salt appended
         * @throws Exception
         */
        protected static byte[] encrypt(String plain, String key, byte[] salt) throws Exception {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key.getBytes("UTF-8"), "AES"),
                    new IvParameterSpec(salt));
            return cipher.doFinal(plain.getBytes("UTF-8"));
        }

        /**
         *
         * @param plain
         * @param key
         * @return data encrypted with key
         * @throws Exception
         */
        protected static byte[] encrypt(String plain, SecretKey key) throws Exception {
            Cipher cipher = Cipher.getInstance("AES", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plain.getBytes("UTF-8"));
        }

        /**
         *
         * @param cipherText
         * @param key
         * @return decrypted bytes of cipher text
         * @throws Exception
         */
        protected static String decrypt(byte[] cipherText, SecretKey key) throws Exception{
            Cipher cipher = Cipher.getInstance("AES", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(cipherText),"UTF-8");
        }

        /**
         *
         * @return freshly generated secret key
         * @throws java.security.NoSuchAlgorithmException
         */
        protected static SecretKey genSecretKey() throws NoSuchAlgorithmException, NoSuchProviderException {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
            keyGen.init(AES_Key_Size);
            return keyGen.generateKey();
        }
    }


}