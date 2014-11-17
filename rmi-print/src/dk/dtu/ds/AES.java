package dk.dtu.ds;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * modified from https://gist.github.com/bricef/2436364
 */
public class AES {
    /**
     * hardcoded key, so we have the same encrypted password versions
     * even if the server is rebooted or something.
     * 16 characters, each of 8 or 16 bits
     * equals 128 or 256 bits key size. depends on the word size of the OS.
     */
    private static final String key = "aL30f-39g(24OfD?";

    /**
     *
     * @param password
     * @param salt
     * @return password encrypted
     */
    public static byte[] encryptPassword(String password, byte[] salt) {
        byte[] encryptedPassword = null;
        try { encryptedPassword = encrypt(password, key, salt); }
        catch (Exception e) { e.printStackTrace(); }
        return encryptedPassword;
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
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key.getBytes("UTF-8"), "AES"),
                new IvParameterSpec(salt));
        return cipher.doFinal(plain.getBytes("UTF-8"));
    }

}