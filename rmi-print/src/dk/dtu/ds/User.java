package dk.dtu.ds;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import static dk.dtu.ds.AES.encryptPassword;

public class User {
    private String username = null;
    private String[] role = null;
    private byte[] encryptedPassword = null,
            salt = new byte[16];

    /**
     *
     * @param u
     * @param p
     */
    public User(String u, String p, String[] r){
        salt = initialisationVector();
        encryptedPassword = encryptPassword(p, salt);
        username = u;
        role = Arrays.copyOf(r, r.length);
    }

    /**
     * modified from stackoverflow.com/questions/18268502/how-to-generate-salt-value-in-java
     * to generate a crypto-random salt
     * @return salt
     */
    private byte[] initialisationVector(){
        Random r = new SecureRandom();
        byte[] ivBytes = new byte[16];
        r.nextBytes(ivBytes);
        return ivBytes;
    }

    /**
     *
     * @return Encrypted password
     */
    public byte[] getEncryptedPassword() {
        return encryptedPassword;
    }

    /**
     *
     * @return Username
     */
    public String getUsername() {
        return username;
    }

    /**
     *
     * @return Role
     */
    public String[] getRole() { return role; }

    /**
     *
     * @return Salt
     */
    public byte[] getSalt() {
        return salt;
    }

}