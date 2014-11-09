package dk.obeid.unused;

import java.io.*;
import java.security.*;
import java.security.spec.*;
import java.util.Properties;

/**
 * modified from http://stackoverflow.com/questions/3441501/java-asymmetric-encryption-preferred-way-to-store-public-private-keys
 * and http://www.javamex.com/tutorials/cryptography/rsa_encryption.shtml
 * and http://snipplr.com/view/18368/
 */
public final class TrustedThirdParty {
    private static final int RSA_Key_Size = 1024;
    private static final TrustedThirdParty ttp = new TrustedThirdParty();
    private static final Properties properties
            = System.getProperties();
    private static final String home
            = properties.get("user.home").toString();
    private static final String separator
            = properties.get("file.separator").toString();
    private static final String dirName
            = "authentication_lab" + separator + "s291452" + separator + "keys" + separator;
    private static final String path = home + separator + dirName;

    /**
     * generates public and private keys for owner and saves them to files
     * @param owner
     */
    public static void generateKeys(String owner) {
        // to print all the keys in the properties map <for testing>
        //properties.list(System.out);
        File dir = new File(path);
        dir.mkdirs(); // create a new directory, will do nothing if directory exists

        try {
            System.out.println("path: " + path);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

            keyGen.initialize(RSA_Key_Size);
            KeyPair keypair = keyGen.genKeyPair();

            System.out.println("Generated Key Pair for " + owner);
            //ttp.dumpKeyPair(keypair);
            ttp.SaveKeyPair(keypair, owner);

            //PublicKey loadedPublicKey = ttp.LoadPublicKey(owner);
            //PrivateKey loadPrivateKey = ttp.LoadPrivateKey(owner);
            //KeyPair loadedKeyPair = new KeyPair(loadedPublicKey, loadPrivateKey);

            //System.out.println("Loaded Key Pair");
            //ttp.dumpKeyPair(loadedKeyPair);
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }

    /**
     *
     * @param owner
     * @return private key for owner
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    public PrivateKey getPrivateKey(String owner) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return ttp.LoadPrivateKey(owner);
    }

    /**
     *
     * @param owner
     * @return public key for owner
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeySpecException
     */
    public PublicKey getPublicKey(String owner) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        return ttp.LoadPublicKey(owner);
    }

    /**
     *
     * @param keyPair
     */
    private void dumpKeyPair(KeyPair keyPair) {
        PublicKey pub = keyPair.getPublic();
        System.out.println("Public Key: " + getHexString(pub.getEncoded()));

        PrivateKey priv = keyPair.getPrivate();
        System.out.println("Private Key: " + getHexString(priv.getEncoded()));
    }

    /**
     *
     * @param b
     * @return
     */
    private String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }

    /**
     *
     * @param keypair
     * @param owner
     * @throws java.io.IOException
     */
    private void SaveKeyPair(KeyPair keypair, String owner) throws IOException {
        PrivateKey servantPrivKey = keypair.getPrivate();
        PublicKey servantPubKey = keypair.getPublic();

        File file = new File(path + owner + ".pub");
        // if file doesnt exists, then create it
        if (!file.exists()) file.createNewFile();

        // Store Public Key.
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(servantPubKey.getEncoded());
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(x509EncodedKeySpec.getEncoded());
        fos.flush();
        fos.close();

        file = new File(path + owner + ".prv");
        // if file doesnt exists, then create it
        if (!file.exists()) file.createNewFile();

        // Store Private Key.
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(servantPrivKey.getEncoded());
        fos = new FileOutputStream(file);
        fos.write(pkcs8EncodedKeySpec.getEncoded());
        fos.flush();
        fos.close();
    }

    /**
     *
     * @param owner
     * @return public key for owner
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private PublicKey LoadPublicKey(String owner)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Public Key.
        File file = new File(path + owner + ".pub");
        FileInputStream fis = new FileInputStream(file);
        byte[] encodedPublicKey = new byte[(int) file.length()];
        fis.read(encodedPublicKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
                encodedPublicKey);
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

        return publicKey;
    }

    /**
     *
     * @param owner
     * @return private key for owner
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private PrivateKey LoadPrivateKey(String owner)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        // Read Private Key.
        File file = new File(path + owner + ".prv");
        FileInputStream fis = new FileInputStream(file);
        byte[] encodedPrivateKey = new byte[(int) file.length()];
        fis.read(encodedPrivateKey);
        fis.close();

        // Generate KeyPair.
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
                encodedPrivateKey);
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        return privateKey;
    }
}

//    private static List<KeyOwnerPair> publicKeys = null;
//
//    private TrustedThirdParty(){}
//
//    private Object readResolve() {
//        return instance;
//    }
//
//    /**
//     *
//     * @return list of public keys
//     */
//    public List<KeyOwnerPair> getPublicKeys() {
//        if (publicKeys == null) publicKeys = new ArrayList<KeyOwnerPair>();
//        return publicKeys;
//    }
//
//    /**
//     * We assume this distribution of keys is done offline.
//     * Generates a key pair. Saves public key with owner in publicKeys.
//     * @param owner
//     * @return the corresponding private key
//     * @throws NoSuchAlgorithmException
//     */
//    public PrivateKey KeyPairGen(String owner) throws NoSuchAlgorithmException {
//        if (publicKeys == null) publicKeys = new ArrayList<KeyOwnerPair>();
//
//        System.out.println("Receiveing new key pair form Trusted Third Party..");
//
//        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//        kpg.initialize(RSA_Key_Size);
//        KeyPair kp = kpg.genKeyPair();
//
//        System.out.println("Key Pair generated..");
//
//        // add public key to list of keys and owner
//        publicKeys.add(new KeyOwnerPair(kp.getPublic(), owner));
//
//        System.out.println("public key added to " + owner + " in list..");
//
//
//        for (KeyOwnerPair k : publicKeys){
//            System.out.println("Owner: " + k.getOwner());
//            System.out.println("PubKey: " + k.getPub());
//        }
//        return kp.getPrivate();
//    }
//
//}
