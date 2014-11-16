package dk.dtu.ds;

import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import static dk.dtu.ds.AES.encryptPassword;

public class PrintServant extends UnicastRemoteObject implements PrintService {
    private String choiceStr;
    private String arg1Str;
    private String arg2Str;
    private String response;

    /**
     *
     * @throws RemoteException
     */
    protected PrintServant() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        super();
    }


    /**
     *
     * @return fresh timestamp for session
     */
    @Override
    public Timestamp getSession() throws IOException {
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

    /**
     *
     * @param username
     * @param password
     * @return whether or not sign on was successful
     */
    public boolean signon(String username, String password) throws Exception {
        List<User> users = getUsers();
        User user = null;

        for (User u : users)
            if (u.getUsername().equalsIgnoreCase(username)) user = u;

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

        if (nep.length != ep.length)
            return false;
        for (int i = 0; i < ep.length; i++)
            if (nep[i] != ep[i]) return false;

        return true;
    }

    /**
     *
     * @param session
     * @return whether or not session is still valid
     */
    public boolean verifySession(Timestamp session) throws Exception {
        if (session != null){
            Calendar cal = Calendar.getInstance();
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
    public String incoming(String choiceByte, String arg1, String arg2) throws Exception {
        if (choiceByte != null) choiceStr = choiceByte;
        if (arg1 != null) arg1Str = arg1;
        if (arg2 != null) arg2Str = arg2;

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
                    else response += "\n";
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
        return response;
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
     * Class for list of queued items
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
