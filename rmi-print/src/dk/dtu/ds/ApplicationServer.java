package dk.dtu.ds;

import java.io.IOException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class ApplicationServer {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        Registry registry = LocateRegistry.createRegistry(8090);
        registry.rebind("print", new PrintServant());
    }
}
