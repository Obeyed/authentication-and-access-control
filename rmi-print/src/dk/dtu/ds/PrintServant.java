package dk.dtu.ds;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.sql.Timestamp;
import java.util.*;

import static dk.dtu.ds.AES.encryptPassword;

public class PrintServant extends UnicastRemoteObject implements PrintService {
    private String response;
    private boolean ACL = true;
    private static String TECHNICIAN = "technician";
    private static String MANAGER = "manager";
    private static String POWERUSER = "powerUser";
    private static String USER = "user";
    private static int SESSION_TIME = 30;

    /**
     * Roles
     */
    private static HashMap<String, List<String>> roles;

    /**
     * List of queued items
     */
    private static List<QueuePair> printQueue = new ArrayList<QueuePair>() {{
        add(new QueuePair(1, "authenticationlab.txt"));
        add(new QueuePair(2, "securitylab.txt"));
        add(new QueuePair(3, "accesscontrol.data"));
        add(new QueuePair(4, "rolebasedaccesscontrol.data"));
        add(new QueuePair(5, "dtu.txt"));
    }
    };

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

    /**
     * List of known users
     */
    private static List<User> users = new ArrayList<User>() {{
   //     add(new User("Bob", "0000", new String[]{TECHNICIAN}));
        add(new User("Alice",   "1234", new String[]{MANAGER}));
        add(new User("Cecilia", "2345", new String[]{POWERUSER}));
        add(new User("David",   "3456", new String[]{USER}));
        add(new User("Erica",   "4567", new String[]{USER}));
        add(new User("Fred",    "5678", new String[]{USER}));
        add(new User("George",  "6789", new String[]{USER, TECHNICIAN}));
        add(new User("Henry",   "7890", new String[]{USER}));
        add(new User("Ida",     "8901", new String[]{POWERUSER}));
    }};

    /**
     * Constructor
     * @throws Exception
     */
    protected PrintServant() throws Exception {
        super();

        Scanner input = new Scanner(System.in);
        byte policy = 0;
        System.out.println("ACL or RBAC?");

        while(policy == 0) {
            String accessPolicy = input.next();
            if (accessPolicy.equalsIgnoreCase("ACL")) {
                System.out.println("Access Control List specified..\nReading ACL file..");
                ACL = true;
                policy = 1;
                readFile(new File("acl.yml"));
            }
            else if (accessPolicy.equalsIgnoreCase("RBAC")) {
                System.out.println("Role Based Access Control specified..\nReading RBAC file..");
                ACL = false;
                policy = 1;
                readFile(new File("rbac.yml"));
            }
            else {
                System.out.println("Unknown access policy..\nEnter either 'ACL' or 'RBAC'");
            }
        }

        System.out.println("Server running.. Run the client.");
   }


    /**
     * Return timestamp
     * @return fresh timestamp for session
     */
    @Override
    public Timestamp getSession() throws IOException {
        return new Timestamp(System.currentTimeMillis());
    }

    /**
     * Read a YAML file
     * @param file YAML file
     * @throws IOException If unable to read file
     */
    @SuppressWarnings("unchecked")
    private static void readFile(File file) throws IOException {
        Yaml yaml = new Yaml();
        FileInputStream fis = new FileInputStream(file);
        roles = (HashMap<String, List<String>>) yaml.load(fis);
        fis.close();
    }

    /**
     *
     * @param username user name
     * @param password password
     * @return whether or not sign on was successful
     */
    public boolean signon(String username, String password) throws Exception {
        User user = null;
        for (User u : users)
            if (u.getUsername().equals(username)) user = u;

        return user != null && verify(password, user.getSalt(), user.getEncryptedPassword());
    }

    /**
     * Verifies a given password
     * @param p password
     * @param s salt
     * @param ep encrypted password
     * @return true if is equal
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
     * verifies a timestamp
     * @param session The timestamp
     * @return whether or not session is still valid
     */
    public boolean verifySession(Timestamp session) throws Exception {
        if (session != null){
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(session.getTime());
            cal.add(Calendar.SECOND, SESSION_TIME);
            Timestamp userSession = new Timestamp(cal.getTime().getTime());
            Timestamp currentTime = new Timestamp(System.currentTimeMillis());

            System.out.println("Verifying session..");
            return userSession.after(currentTime);
        }
        return false;
    }

    /**
     * Incoming requests from client
     * @param choiceStr Choice for the switch
     * @param arg1Str First arguemnt, if operation needs it
     * @param arg2Str Second argument, if operations needs it
     * @param userName User name of user logged into client
     * @return response
     * @throws Exception if something goes wrong
     */
    @Override
    public String incoming(String choiceStr, String arg1Str, String arg2Str, String userName) throws Exception {
        boolean allowed = false;

        User user = null;
        for (User u : users) {
            if (u.getUsername().equals(userName)){
                for(int i = 0; i < u.getRole().length; i++)
                    System.out.println(u.getRole()[i]);
                user = u;
                break;
            }
        }

        int choiceInt = Integer.parseInt(choiceStr);
        switch (choiceInt) {
            case 1:
                if (ACL) {
                    if (!roles.get("print").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "print");
                }

                if (allowed) {
                    if (arg1Str != null && arg2Str != null)
                        response = (print(arg1Str, arg2Str));
                    else
                        response = "Arguments cannot be null..";
                }
                break;
            case 2:
                if (ACL) {
                    if (!roles.get("queue").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "queue");
                }

                if (allowed) {
                    response = null;
                    for (String q : queue()) {
                        if (response == null) response = "";
                        else response += "\n";
                        response += q;
                    }
                }
                break;
            case 3:
                if (ACL) {
                    if (!roles.get("topQueue").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "topQueue");
                }

                if (allowed) {
                    if (arg1Str != null)
                        response = topQueue(Integer.parseInt(arg1Str));
                    else
                        response = "Arguments cannot be null..";
                }
                break;
            case 4:
                if (ACL) {
                    if (!roles.get("start").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "start");
                }

                if (allowed)
                    response = start();
                break;
            case 5:
                if (ACL) {
                    if (!roles.get("stop").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "stop");
                }

                if (allowed)
                    response = stop();
                break;
            case 6:
                if (ACL) {
                    if (!roles.get("restart").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "restart");
                }

                if (allowed)
                    response = restart();
                break;
            case 7:
                if (ACL) {
                    if (!roles.get("status").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "status");
                }

                if (allowed)
                    response = status();
                break;
            case 8:
                System.out.println("inside switch");
                if (ACL) {
                    if (!roles.get("readConfig").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                } else {
                    allowed = verifyRBAC(user.getRole(), "readConfig");
                }

                if (allowed){
                    if (arg1Str != null)
                        response = readConfig(arg1Str);
                    else
                        response = "Arguments cannot be null..";
                }
                break;
            case 9:
                if(ACL) {
                    if (!roles.get("setConfig").contains(userName))
                        return "You are not authorized to perform the action.."; // ACL roles
                    allowed = true;
                }
                else {
                    allowed = verifyRBAC(user.getRole(), "setConfig");
                }

                if (allowed){
                    if (arg1Str != null && arg2Str!= null)
                        response = (setConfig(arg1Str, arg2Str));
                    else
                        response = "Arguments cannot be null..";
                }
                break;
            default:
                response = "Unknown command..";
                break;
        }
        return response;
    }

    /**
     * Verifies access persmissions according to RBAC
     * @param rs Array of roles
     * @param operation The operation
     * @return true if is allowed
     */
    private static boolean verifyRBAC(String[] rs, String operation){
        for (int i = 0; i < rs.length; i++) {
            if (roles.get(rs[i]).contains(operation)) {
                return true;
            }
        }
        return false;
    }

    /*
     * AVAILABLE SERVICES
     */
    // prints file filename on the specified printer
    private String print(String filename, String printer) throws RemoteException {
        return "Printing " + filename + " on printer " + printer;
    }

    // lists the print printQueue on the user's display in lines of the form <job number>   <file name>
    private List<String> queue() throws RemoteException {
        List<String> printList = new ArrayList<String>();

        for (QueuePair q : printQueue)
          printList.add("<" + Integer.toString(q.jobNumber) + ">  <" + q.fileName + ">");

        return printList;
    }

    // moves job to the top of the printQueue
    private String topQueue(int job) throws RemoteException {
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
    private String start() throws RemoteException {
        return "Print server booted";
    }

    // stops the print server
    private String stop() throws RemoteException {
        return "Print server stopped";
    }

    // stops the print server, clears the print printQueue and starts the print server again
    private String restart() throws RemoteException {
        System.out.println(stop());
        printQueue = null;
        System.out.println(start());
        return "Printer rebooted and print queue is empty.";
    }

    // prints status of printer on the user's display
    private String status() throws RemoteException {
        return "Status unknown";
    }

    // prints the value of the parameter on the user's display
    private String readConfig(String parameter) throws RemoteException {
        return "Configuration: " + parameter;
    }

    // sets the parameter to value
    private String setConfig(String parameter, String value) throws RemoteException {
        return String.format("Written configuration: %s", parameter = value); // whaa?
    }

}
