package dk.obeid;

//import dk.obeid.unused.TrustedThirdParty;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileOutputStream;
import java.io.IOException;
//import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
//import java.sql.Date;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.*;

import static dk.obeid.PrintServant.AES.*;
//import static dk.obeid.PrintServant.RSA.rsaDecrypt;
//import static dk.obeid.PrintServant.RSA.rsaEncryptPriv;
//import static dk.obeid.PrintServant.RSA.rsaEncryptPub;

public class PrintServant extends UnicastRemoteObject implements PrintService {
//    private static SecretKey sharedKey; // we assume that the shared key was distributed by an asymmetric handshake
    private String choiceStr;
    private String arg1Str;
    private String arg2Str;
    private String response;
//    private static String handshakeUser;
//    private static int initialNonce = -1;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS");
//    private static Date convertedDate;
//    private static final TrustedThirdParty ttp = new TrustedThirdParty();
//    private static PrivateKey privateKey;

    /**
     *
     * @throws RemoteException
     */
    protected PrintServant() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        super();
//        generateWriteSecretKey();
//        ttp.generateKeys("servant");
//        for(User u : getUsers())
//            ttp.generateKeys(u.getUsername());
//
//        privateKey = ttp.getPrivateKey("servant");
    }

//    @Override
//    public SecretKey getSharedKey() throws IOException {
//        return readSecretKey();
//    }

    @Override
    /**
     *
     * @return fresh timestamp for session
     */
 //   public byte[] getSession() throws IOException {
    public Timestamp getSession() throws IOException {
        //String t = new Timestamp(System.currentTimeMillis()).toString();
        //System.out.println("new session from server: " + t);
        // return encryptData(t, readSecretKey());
        return new Timestamp(System.currentTimeMillis());
    }

    /**
     *
     * @return list of users
     */
    public static List<User> getUsers() {
        return users;
    }

    /**
     * list of queued items
     */
    private static List<QueuePair> printQueue = new ArrayList<QueuePair>() {{
          add(new QueuePair(1, "authenticationlab.txt"));
          add(new QueuePair(2, "securitylab.txt"));
        }
    };
    /**
     * list of known users
     */
    private static List<User> users = new ArrayList<User>() {{
        add(new User("obeid", "1234"));
    }};

//    /**
//     *
//     * @param user
//     * @param timestamp
//     * @return if handshake succeds ,
//     *         else if user is not found return "user not found",
//     *         else if timestamp is too old return "handshake too old".
//     * @throws IllegalBlockSizeException
//     * @throws BadPaddingException
//     * @throws InvalidKeyException
//     * @throws NoSuchAlgorithmException
//     * @throws NoSuchPaddingException
//     * @throws UnsupportedEncodingException
//     */
//    public static byte[][] initialHandshake(byte[] user, byte[] timestamp) throws Exception {
//        if(privateKey == null) privateKey = ttp.getPrivateKey("servant");
//        handshakeUser = rsaDecrypt(user, privateKey);
//        initialNonce = -1;
//        boolean identified = false;
//
//        for (User u : users) if (u.getUsername() == handshakeUser) identified = true;
//        if (!identified)
//            return new byte[][]{
//                rsaEncryptPriv("User not found".getBytes(), privateKey),
//                null
//            };
//
//        System.out.println("-- From server: User identified..");
//
//        Date decryptedDate = (Date) dateFormat.parse(rsaDecrypt(timestamp, handshakeUser));
//        Timestamp actualTimestamp = new Timestamp(decryptedDate.getTime());
//        System.out.println("--- TEST SERVANT INITIAL TIMESTAMP: " + actualTimestamp.toString());
//
//        Calendar cal = Calendar.getInstance();
//        cal.setTimeInMillis(actualTimestamp.getTime());
//        cal.add(Calendar.SECOND, 5); // must not be older than 5 seconds
//        Timestamp receivedTimestamp = new Timestamp(cal.getTime().getTime()); // received stamp + five seconds
//        Timestamp currentTime = new Timestamp(System.currentTimeMillis()); // actual stamp
//
//        if (!receivedTimestamp.after(currentTime))
//            return new byte[][]{
//                    rsaEncryptPriv("Handshake too old".getBytes(), privateKey),
//                    null
//            };
//
//        Random rn = new Random();
//        initialNonce = rn.nextInt() % 100; // nonce
//
//        return new byte[][]{
//                rsaEncryptPriv("servant".getBytes(), privateKey),
//                rsaEncryptPub(Integer.toString(initialNonce).getBytes(), handshakeUser)
//        };
//    }

//    /**
//     *
//     * @param replyServant
//     * @param replyNonce
//     * @param replyTimestamp
//     * @return
//     * @throws Exception
//     */
//    public static byte[] handshakeResponse(byte[] replyServant, byte[] replyNonce, byte[] replyTimestamp) throws Exception {
//        if ("servant" != rsaDecrypt(replyServant, handshakeUser)) {
//            System.out.println("-- From server: Wrong first argument..");
//            return null;
//        }
//
//        if (initialNonce != -1 && Integer.toString(initialNonce) != rsaDecrypt(replyNonce, handshakeUser)) {
//            System.out.println("-- From server: Wrong second argument..");
//            return null;
//        }
//
//        Date decryptedDate = (Date) dateFormat.parse(rsaDecrypt(replyTimestamp, handshakeUser));
//        Timestamp actualTimestamp = new Timestamp(decryptedDate.getTime());
//
//        Calendar cal = Calendar.getInstance();
//        cal.setTimeInMillis(actualTimestamp.getTime());
//        cal.add(Calendar.SECOND, 5); // must not be older than 5 seconds
//        Timestamp receivedTimestamp = new Timestamp(cal.getTime().getTime());
//
//        Timestamp currentTime = new Timestamp(System.currentTimeMillis());
//
//        if (!receivedTimestamp.after(currentTime)){
//            System.out.println("-- From server: Timestamp too old ( " + receivedTimestamp.toString() + " )");
//            return null;
//        }
//
//        sharedKey = generateWriteSecretKey();
//        System.out.println("---- TEST KEY: " + sharedKey.toString());
//
//        return rsaEncryptPub(sharedKey.getEncoded(), handshakeUser); // reply with a shared key
//    }

    /**
     *
     * @param username
     * @param password
     * @return whether or not sign on was successful
     */
    // public boolean signon(byte[] username, byte[] password) throws Exception {
    public boolean signon(String username, String password) throws Exception {
//        sharedKey = readSecretKey();
//        String decryptedUser = decrypt(username, sharedKey);
//        String decryptedPassword = decrypt(password, sharedKey);

        List<User> users = getUsers();
        User user = null;
        for (User u : users) if (u.getUsername().equalsIgnoreCase(username)) user = u;

        return user != null && verify(password, user.getSalt(), user.getEncryptedPassword());
    }

    /**
     *
     * @param p
     * @param s
     * @param ep
     * @return
     */
    private static boolean verify(String p, byte[] s, byte[] ep){
        byte[] nep = encryptPassword(p, s);

        if (nep.length != ep.length) return false;
        for (int i = 0; i < ep.length; i++) if (nep[i] != ep[i]) return false;
        return true;
    }

    /**
     *
     * @param session
     * @return whether or not session is still valid
     */
//    public boolean verifySession(byte[] session) throws Exception {
    public boolean verifySession(Timestamp session) throws Exception {
//        Date decryptedSession = (Date) dateFormat.parse(decrypt(session, readSecretKey()));
//        Timestamp actualSession = new Timestamp(decryptedSession.getTime());

        if (session != null){
            Calendar cal = Calendar.getInstance();
//            cal.setTimeInMillis(actualSession.getTime());
            cal.setTimeInMillis(session.getTime());
            cal.add(Calendar.SECOND, 10); // has access for 10 seconds
            Timestamp userSession = new Timestamp(cal.getTime().getTime());
            Timestamp currentTime = new Timestamp(System.currentTimeMillis());

            System.out.println("Verifying session..");
            return userSession.after(currentTime);
        }
        return false;
    }

    @Override
//    public byte[] incoming(byte[] choiceByte, byte[] arg1, byte[] arg2) throws Exception {
    public String incoming(String choiceByte, String arg1, String arg2) throws Exception {
//        sharedKey = readSecretKey();
        //decrypt data
        if (choiceByte != null) choiceStr = choiceByte; //decrypt(choiceByte, sharedKey);
        if (arg1 != null) arg1Str = arg1; //decrypt(arg1, sharedKey);
        if (arg2 != null) arg2Str = arg2; //decrypt(arg2, sharedKey);

        int choiceInt = Integer.parseInt(choiceStr);
        switch (choiceInt) {
            case 1:
                if (arg1Str != null && arg2Str!= null) response = (print(arg1Str, arg2Str));
                else throw new Exception("arguments cannot be null");
                break;
            case 2:
                response = null;
                for (String q : queue()) {
                    if (response == null ) response = "";
                    else {
                        response += "\n";
                    }
                    response += q;
                }
                break;
            case 3:
                if (arg1Str != null) response = topQueue(Integer.parseInt(arg1Str));
                else throw new Exception("arguments cannot be null");
                break;
            case 4:
                response = start();
                break;
            case 5:
                response = stop();
                break;
            case 6:
                response = restart();
                break;
            case 7:
                response = status();
                break;
            case 8:
                if (arg1Str != null) response = readConfig(arg1Str);
                else throw new Exception("arguments cannot be null");
                break;
            case 9:
                if (arg1Str != null && arg2Str!= null) response = (setConfig(arg1Str, arg2Str));
                else throw new Exception("arguments cannot be null");
                break;
            default:
                response = "Unknown command..";
                break;
        }
        //encrypt response
        return response; //encryptData(response, sharedKey);
    }

    /*
     * AVAILABLE SERVICES
     */
    // prints file filename on the specified printer
    public String print(String filename, String printer) throws RemoteException {
        return "Printing " + filename + " on printer " + printer;
    }

    // lists the print printQueue on the user's display in lines of the form <job number>   <file name>
    public List<String> queue() throws RemoteException {
        List<String> printList = new ArrayList<String>();

        for (QueuePair q : printQueue)
          printList.add("<" + Integer.toString(q.jobNumber) + ">  <" + q.fileName + ">");

        return printList;
    }

    // moves job to the top of the printQueue
    public String topQueue(int job) throws RemoteException {
        QueuePair qp = null;
        int index = -1;
        for (QueuePair q : printQueue){
            if (q.jobNumber == job){
                qp = q;
                printQueue.remove(q);
                break;
            }
        }
        if (null == qp) return "Job number " + job + " was not foud in the queue..";
        else {
          printQueue.add(0, qp);
          return "Moved job " + job + " to top of queue..";
        }
    }

    // starts the print server
    public String start() throws RemoteException {
        return "Print server booted";
    }

    // stops the print server
    public String stop() throws RemoteException {
        return "Print server stopped";
    }

    // stops the print server, clears the print printQueue and starts the print server again
    public String restart() throws RemoteException {
        System.out.println(stop());
        printQueue = null;
        System.out.println(start());
        return "Printer rebooted and print queue is empty.";
    }

    // prints status of printer on the user's display
    public String status() throws RemoteException {
        return "Status unknown";
    }

    // prints the value of the parameter on the user's display
    public String readConfig(String parameter) throws RemoteException {
        return "Configuration: " + parameter;
    }

    // sets the parameter to value
    public String setConfig(String parameter, String value) throws RemoteException {
        return String.format("Written configuration: %s", parameter = value); // whaa?
    }

    /**
     * modified from https://gist.github.com/bricef/2436364
     */
    protected static class AES {
        /**
         * hardcoded key, so we have the same encrypted password versions
         * even if the server is rebooted or something.
         * 16 characters, each of 8 or 16 bits
         * equals 128 or 256 bits key size. depends on the word size of the OS.
         */
        private static final String key = "aL30f-39g(24OfD?";
//        /**
//         * AES key size
//         */
//        private static final int AES_Key_Size = 256;

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

//        /**
//         *
//         * @param data
//         * @param secretKey
//         * @return data encrypted
//         */
//        protected static byte[] encryptData(String data, SecretKey secretKey){
//            byte[] encrypted = null;
//            try {
//                encrypted = encrypt(data, secretKey);
//            } catch (Exception e) {
//                e.printStackTrace();
//            }
//            return encrypted;
//        }

        /**
         *
         * @param plain
         * @param key
         * @param salt
         * @return password encrypted with a salt appended
         * @throws Exception
         */
        protected static byte[] encrypt(String plain, String key, byte[] salt) throws Exception {
            System.out.println("Server: encrypting password..");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key.getBytes("UTF-8"), "AES"),
                    new IvParameterSpec(salt));
            return cipher.doFinal(plain.getBytes("UTF-8"));
        }

//        /**
//         *
//         * @param plain
//         * @param key
//         * @return data encrypted with key
//         * @throws Exception
//         */
//        protected static byte[] encrypt(String plain, SecretKey key) throws Exception {
//            Cipher cipher = Cipher.getInstance("AES", "SunJCE");
//            cipher.init(Cipher.ENCRYPT_MODE, key);
//            return cipher.doFinal(plain.getBytes("UTF-8"));
//        }

//        /**
//         *
//         * @param cipherText
//         * @param key
//         * @return decrypted bytes of cipher text
//         * @throws Exception
//         */
//        protected static String decrypt(byte[] cipherText, SecretKey key) throws Exception{
//            Cipher cipher = Cipher.getInstance("AES", "SunJCE");
//            cipher.init(Cipher.DECRYPT_MODE, key);
//            return new String(cipher.doFinal(cipherText),"UTF-8");
//        }
//
//        /**
//         *
//         * @return freshly generated secret key
//         * @throws java.security.NoSuchAlgorithmException
//         */
//        protected static void generateWriteSecretKey() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
//            Properties properties = System.getProperties();
//            String home = properties.get("user.home").toString();
//            String separator = properties.get("file.separator").toString();
//            String dirName = "authentication_lab" + separator + "s142952" + separator + "shared_key" + separator;
//            String path = home + separator + dirName;
//
//            File dir = new File(path);
//            dir.mkdirs(); // create a new directory, will do nothing if directory exists
//
//            File file = new File(path + "shared.key");
//            if (!file.exists()) file.createNewFile(); // if file doesnt exists, then create it
//
//            KeyGenerator keyGen = KeyGenerator.getInstance("AES", "SunJCE");
//            keyGen.init(AES_Key_Size);
//            SecretKey aesKey = keyGen.generateKey();
//
//            byte[] encoded = aesKey.getEncoded();
//            /* Now store "encoded" somewhere. For example, display the key and
//               ask the user to write it down. */
//            FileOutputStream fos = new FileOutputStream(file);
//
//            System.out.println(getHexString(encoded));
//
//            fos.write(getHexString(encoded).getBytes());
//            fos.flush();
//            fos.close();
//            System.out.println("Shared key stored..");
//
//        }
//
//        public static SecretKey readSecretKey() throws IOException {
//            Properties properties = System.getProperties();
//            String home = properties.get("user.home").toString();
//            String separator = properties.get("file.separator").toString();
//            String dirName = "authentication_lab" + separator + "s291452" + separator + "shared_key" + separator;
//            String path = home + separator + dirName;
//
//            File file = new File(path + "shared.key");
//            FileInputStream fis = new FileInputStream(file);
//            byte[] encodedSharedKey = new byte[(int) file.length()];
//            fis.read(encodedSharedKey);
//            fis.close();
//            byte[] encoded = new BigInteger(new String(encodedSharedKey, "UTF-8"), 16).toByteArray();
//
//            System.out.println("Returning shared key..");
//
//            return new SecretKeySpec(encoded, "AES");
//        }
//
//
//        /**
//         *
//         * @param b
//         * @return
//         */
//        private static String getHexString(byte[] b) {
//            String result = "";
//            for (int i = 0; i < b.length; i++) {
//                result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
//            }
//            return result;
//        }

    }

    /**
     * modified from http://stackoverflow.com/questions/3441501/java-asymmetric-encryption-preferred-way-to-store-public-private-keys
     * and http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
     */
//    protected static class RSA {
//        /**
//         * Encrypts data with public key of owner.
//         * @param data
//         * @param owner
//         * @return If owner is known, data is encrypted with public key of owner.
//         *         Otherwise, an empty byte is returned.
//         * @throws javax.crypto.NoSuchPaddingException
//         * @throws NoSuchAlgorithmException
//         * @throws javax.crypto.BadPaddingException
//         * @throws javax.crypto.IllegalBlockSizeException
//         * @throws java.security.InvalidKeyException
//         */
//        protected static byte[] rsaEncryptPub(byte[] data, String owner) throws Exception {
//            PublicKey pubKey = ttp.getPublicKey(owner);
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
//            byte[] cipherData = cipher.doFinal(data);
//            return cipherData;
//        }
//
//        /**
//         *
//         * @param data
//         * @param privKey
//         * @return Encrypted data with private key.
//         * @throws NoSuchPaddingException
//         * @throws NoSuchAlgorithmException
//         * @throws BadPaddingException
//         * @throws IllegalBlockSizeException
//         * @throws InvalidKeyException
//         */
//        protected static byte[] rsaEncryptPriv(byte[] data, PrivateKey privKey) throws NoSuchPaddingException,
//                NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchProviderException {
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.ENCRYPT_MODE, privKey);
//            byte[] cipherData = cipher.doFinal(data);
//            return cipherData;
//        }
//
//        /**
//         *
//         * @param data
//         * @param privKey public or private key
//         * @return decrypted version of data
//         * @throws NoSuchPaddingException
//         * @throws NoSuchAlgorithmException
//         * @throws BadPaddingException
//         * @throws IllegalBlockSizeException
//         * @throws InvalidKeyException
//         */
//        protected static String rsaDecrypt(byte[] data, PrivateKey privKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
//                BadPaddingException, IllegalBlockSizeException, InvalidKeyException, IOException, NoSuchProviderException, InvalidKeySpecException {
//            if(privKey == null)  ttp.getPrivateKey("servant");
//
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, privKey);
//            byte[] plainData = cipher.doFinal(data);
//            return new String(cipher.doFinal(plainData),"UTF-8");
//        }
//
//        protected static String rsaDecrypt(byte[] data, String owner) throws Exception {
//            PublicKey pubKey = ttp.getPublicKey(owner);
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, pubKey);
//            byte[] plainData = cipher.doFinal(data);
//            return new String(cipher.doFinal(plainData),"UTF-8");
//        }
//    }

    /**
     * class for list of queued items
     */
    protected static class QueuePair {
        private int jobNumber;
        private String fileName;

        private QueuePair() {}

        private QueuePair(int j, String f) {
            jobNumber = j;
            fileName = f;
        }
    }

}
