package dk.dtu.ds;

import java.io.IOException;
import java.rmi.Remote;
import java.sql.Timestamp;

public interface PrintService extends Remote {
    public String incoming(String choiceByte, String arg1, String arg2, String user) throws Exception;

    public Timestamp getSession() throws IOException;

    public boolean verifySession(Timestamp session) throws Exception;

    public boolean signon(String user, String password) throws Exception;
}
