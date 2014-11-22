package dk.dtu.ds;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ApplicationServer {
    /**
     * Run this main first. When this service is running, run the client.
     * @param args Arguments
     * @throws Exception if something goes wrong
     */
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.createRegistry(8080);
        registry.rebind("print", new PrintServant());
    }
}
