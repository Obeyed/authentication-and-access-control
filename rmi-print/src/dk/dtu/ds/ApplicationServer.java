package dk.dtu.ds;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ApplicationServer {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(8080);
        registry.rebind("print", new PrintServant());
    }
}
