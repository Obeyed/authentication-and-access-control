package dk.obeid;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.sql.Timestamp;
import java.util.List;

public interface PrintService extends Remote {
//    // prints file filename on the specified printer
//    public String print(String filename, String printer) throws RemoteException;
//    // lists the print queue on the user's display in lines of the form <job number>   <file name>
//    public List<String> queue() throws RemoteException;
//    // moves job to the top of the queue
//    public String topQueue(int job) throws RemoteException;
//    // starts the print server
//    public String start() throws RemoteException;
//    // stops the print server
//    public String stop() throws RemoteException;
//    // stops the print server, clears the print queue and starts the print server again
//    public String restart() throws RemoteException;
//    // prints status of printer on the user's display
//    public String status() throws RemoteException;
//    // prints the value of the parameter on the user's display
//    public String readConfig(String parameter) throws RemoteException;
//    // sets the parameter to value
//    public String setConfig(String parameter, String value) throws RemoteException;

//    public byte[] incoming(byte[] choiceByte) throws Exception;
//    public byte[] incoming(byte[] choiceByte, byte[] arg1) throws Exception;
//    public byte[] incoming(byte[] choiceByte, byte[] arg1, byte[] arg2) throws Exception;

    public String incoming(String choiceByte, String arg1, String arg2) throws Exception;

//    public byte[] getSession() throws IOException;
    public Timestamp getSession() throws IOException;

//    public SecretKey getSharedKey() throws IOException;

//    public boolean verifySession(byte[] session) throws Exception;
    public boolean verifySession(Timestamp session) throws Exception;

//    public boolean signon(byte[] user, byte[] password) throws Exception;
    public boolean signon(String user, String password) throws Exception;
}
