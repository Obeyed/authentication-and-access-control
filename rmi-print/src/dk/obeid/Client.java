package dk.obeid;

import dk.obeid.unused.TrustedThirdParty;

import javax.crypto.*;
//import java.io.UnsupportedEncodingException;
import java.rmi.Naming;
import java.sql.Date;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Scanner;

import static dk.obeid.Client.AES.decrypt;
import static dk.obeid.Client.AES.encryptData;
//import static dk.obeid.Client.RSA.rsaDecrypt;
//import static dk.obeid.Client.RSA.rsaEncryptPriv;

public class Client {
    private static PrintService service;
    private static Timestamp session;
//    private static PrivateKey privateKey;
    private static SecretKey sharedKey;
//    private static String initialServerResponse;
//    private static String initialNonceResponse;
//    private static boolean publicKeyHandshake = false;
    private static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS");
    private static Date decryptedSession;
    private static final TrustedThirdParty ttp = new TrustedThirdParty();

    public static void main(String[] args) throws Exception {


        /*    user  | password
         * ----------------------
         *    obeid |  1234
         */

        Scanner input = new Scanner(System.in);
        boolean authenticated = false,
                terminate = false;
        String user = null,
                password = null;
        service = (PrintService) Naming.lookup("rmi://localhost:8090/print");

        /**
         * We assume that this key has had been received offline,
         * but for this purpose we generate a new key pair
         */
        sharedKey = service.getSharedKey();
        for (byte b : sharedKey.getEncoded())
            System.out.print(b);

        System.out.println();

//        System.out.println("Requested Key Pair..");
//        privateKey = ttp.getPrivateKey("obeid");
//        for (byte b : privateKey.getEncoded())
//            System.out.print(b);
//        System.out.println();

        while (!terminate){
            System.out.println("In ourtermost loop..");
            authenticated = false;
//            while (!authenticated && !publicKeyHandshake) {
            while (!authenticated) {
                System.out.println("In innermost loop..");
                authenticated = giveAccessInfo(input, user, password);
//                if (!publicKeyHandshake) {
//                    System.out.println("Asymmetric handshake unsuccesful..\nGoodbye.");
//                    System.exit(1);
//                }
            }
            terminate = whatToChose(input);
        }
    }

    /**
     *
     * @param input
     * @param user
     * @param password
     * @return whether or not the user can continue to the services
     * @throws InterruptedException
     */
    private static boolean giveAccessInfo(Scanner input, String user, String password) throws Exception {
        if (session != null && service.verifySession(encryptData(session.toString(), sharedKey))) {
            System.out.println("Verified");
            return true;
        }
        if(session != null) System.out.println("Session expired! Sign in again.");

        System.out.print("Enter username: ");
        user = input.nextLine();

        System.out.print("Enter password: ");
        password = input.nextLine();

//        if(!sendInitialHandshake(user)){
//            publicKeyHandshake = false;
//            return false;
//        }
//
//        if(!sendResponseAndFinalize(initialServerResponse, initialNonceResponse)) {
//            publicKeyHandshake = false;
//            return false;
//        }

        if (service.signon(encryptData(user, sharedKey), encryptData(password, sharedKey))) {
            System.out.println("Verifying sign in..");
            System.out.println("Receiving session info..");

            decryptedSession = (Date) dateFormat.parse(decrypt(service.getSession(), sharedKey));
            session = new Timestamp(decryptedSession.getTime());
            System.out.println("new session: " + session.toString());

            System.out.println("Welcome to print service!");
//            publicKeyHandshake = true;
            return true;
        }
        else {
            System.out.println("Verifying sign in..");
//            publicKeyHandshake = false;
            Thread.sleep(5000);
            System.out.println("ACCESS DENIED");
            return false;
        }
    }

//    private static boolean sendInitialHandshake(String user) throws Exception {
//        Timestamp handshakeTime = new Timestamp(System.currentTimeMillis());
//
//        System.out.println("-- TEST CLIENT INITIAL HANDSHAKE TIMESTAMP: " + handshakeTime.toString());
//
//        System.out.println("-- Initiating public key handshake..");
//
//        byte[][] response = PrintServant.initialHandshake(rsaEncryptPriv(user.getBytes(), privateKey),
//                RSA.rsaEncryptPub(handshakeTime.toString().getBytes(), "servant"));
//
//        System.out.println("-- Reading response..");
//
//        if (response[1] == null) {
//            System.out.println("+++ Response from server: " + rsaDecrypt(response[0], "servant"));
//            return false;
//        }
//
//        initialServerResponse = rsaDecrypt(response[0], "servant");
//        initialNonceResponse = rsaDecrypt(response[1], privateKey);
//
//        System.out.println("-- Initial handshake completed..");
//
//        return true;
//    }
//
//    private static boolean sendResponseAndFinalize(String initialServerResponse, String initialNonceResponse) throws Exception {
//        String replyTime = new Timestamp(System.currentTimeMillis()).toString();
//        System.out.print("-- Client response time: " + replyTime);
//
//        byte[] finalReply = PrintServant.handshakeResponse(rsaEncryptPriv(initialServerResponse.getBytes(),
//                        privateKey),
//                RSA.rsaEncryptPub(initialNonceResponse.getBytes(), "servant"),
//                RSA.rsaEncryptPub(replyTime.getBytes(), "servant"));
//
//        if(finalReply == null) {
//            System.out.println("--- Server did not accept. See server response..");
//            return false;
//        }
//
//        rsaDecrypt(finalReply, privateKey);
//
//        sharedKey = new SecretKeySpec(finalReply, 0, finalReply.length, "AES");
//        System.out.println("--- TEST CLIENT KEY: " + sharedKey.toString());
//
//        return true;
//    }

    /**
     * actions are encrypted before sent to the server
     * @param input
     * @return whether or not to terminate
     * @throws Exception
     */
    private static boolean whatToChose(Scanner input) throws Exception {
        String choiceStr = null,
                arg1Str = null,
                arg2Str = null;
        int choice = 0;

        System.out.println();
        System.out.println("Possible actions:");
        System.out.println("1  - print\n" +
                "2  - queue\n" +
                "3  - top queue\n" +
                "4  - start\n" +
                "5  - stop\n" +
                "6  - restart\n" +
                "7  - status\n" +
                "8  - read configuration\n" +
                "9  - set configuration\n" +
                "00 - exit");

        choiceStr= input.nextLine();
        choice = Integer.parseInt(choiceStr);

        switch (choice) {
            case 1:
                System.out.println("What to print: ");
                arg1Str = input.nextLine();
                System.out.println("On which printer: ");
                arg2Str = input.nextLine();
                System.out.println(send(choiceStr, arg1Str, arg2Str));
                break;
            case 2:
                System.out.println(send(choiceStr));
                break;
            case 3:
                System.out.println("Which job do you want moved to top: ");
                arg1Str = input.nextLine();
                System.out.println(send(choiceStr, arg1Str));
                break;
            case 4:
                System.out.println(send(choiceStr));
                break;
            case 5:
                System.out.println(send(choiceStr));
                break;
            case 6:
                System.out.println(send(choiceStr));
                break;
            case 7:
                System.out.println(send(choiceStr));
                break;
            case 8:
                System.out.println("What parameter: ");
                arg1Str = input.nextLine();
                System.out.println(send(choiceStr, arg1Str));
                break;
            case 9:
                System.out.println("What parameter: ");
                arg1Str = input.nextLine();
                System.out.println("What value: ");
                arg2Str = input.nextLine();
                System.out.println(send(choiceStr, arg1Str, arg2Str));
                break;
            case 00:
                System.out.println("Goodbye");
                return true;
            default:
                System.out.println("Unknown command..");
                break;
        }
        Thread.sleep(1000);
        return false;
    }

    private static String send(String choice) throws Exception {
        return send(choice, null);
    }

    private static String send(String choice, String arg1) throws Exception {
        return send(choice, arg1, null);
    }

    private static String send(String choice, String arg1, String arg2) throws Exception {
        byte[] encrypted = service.incoming(
                encryptData(choice, sharedKey),
                encryptData(arg1, sharedKey),
                encryptData(arg2, sharedKey)
        );

        return decrypt(encrypted, sharedKey);
    }

    /**
     * modified from https://gist.github.com/bricef/2436364
     * same as from PrintServant but only with the relevant methods.
     */
    protected static class AES {
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
    }

//    /**
//     * modified from http://stackoverflow.com/questions/3441501/java-asymmetric-encryption-preferred-way-to-store-public-private-keys
//     * and http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
//     */
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
//            System.out.println("RSA ENCRYPT PUBLIC!");
//            PublicKey pubKey = ttp.getPublicKey(owner);
//
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
//
//            System.out.println("RSA ENCRYPT PRIVATE!");
//
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
//        protected static String rsaDecrypt(byte[] data, PrivateKey privKey) throws NoSuchPaddingException,
//                NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, UnsupportedEncodingException, NoSuchProviderException {
//            System.out.println("RSA DECRYPT PRIVATE");
//
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, privKey);
//            byte[] plainData = cipher.doFinal(data);
//            return new String(cipher.doFinal(plainData),"UTF-8");
//        }
//
//        protected static String rsaDecrypt(byte[] data, String owner) throws Exception {
//
//            System.out.println("RSA DECRYPT!");
//            PublicKey pubKey = ttp.getPublicKey(owner);
//
//            Cipher cipher = Cipher.getInstance("RSA");
//            cipher.init(Cipher.DECRYPT_MODE, pubKey);
//            byte[] plainData = cipher.doFinal(data);
//            return new String(cipher.doFinal(plainData),"UTF-8");
//        }
//    }

}
