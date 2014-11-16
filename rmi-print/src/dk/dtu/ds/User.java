package dk.dtu.ds;

import java.security.SecureRandom;
import java.util.Random;

import static dk.dtu.ds.AES.encryptPassword;

public class User {
    private String username = null;
    private byte[] encryptedPassword = null,
            salt = new byte[16];

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
        Random r = new SecureRandom();
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

}