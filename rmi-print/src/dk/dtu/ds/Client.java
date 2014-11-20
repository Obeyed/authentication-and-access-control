package dk.dtu.ds;

import java.rmi.Naming;
import java.sql.Timestamp;
import java.util.Scanner;

public class Client {
    private static PrintService service;
    private static Timestamp session;
    private static String user;

    public static void main(String[] args) throws Exception {
        Scanner input = new Scanner(System.in);
        boolean authenticated = false,
                terminate = false;
        String password = null;
        service = (PrintService) Naming.lookup("rmi://localhost:8080/print");

        while (!terminate){
            authenticated = false;
            while (!authenticated) authenticated = giveAccessInfo(input, password);
            terminate = whatToChose(input);
        }
    }

    /**
     *
     * @param input
     * @param password
     * @return whether or not the user can continue to the services
     * @throws Exception
     */
    private static boolean giveAccessInfo(Scanner input, String password) throws Exception {
        if (session != null) System.out.println("Verifying session..");
        if (session != null && service.verifySession(session)) {
            System.out.println("Verified");
            return true;
        }
        if(session != null) System.out.println("Session expired! Sign in again.");

        System.out.print("Enter username: ");
        user = input.nextLine();

        System.out.print("Enter password: ");
        password = input.nextLine();

        // We assume that the connection is secure and private
        if (service.signon(user, password)) {
            System.out.println("Verifying sign in..");
            System.out.println("Receiving session info..");

            session = service.getSession();

            System.out.println("Welcome to print service!");
            return true;
        }
        else {
            System.out.println("Verifying sign in..");
            Thread.sleep(5000);
            System.out.println("ACCESS DENIED");
            return false;
        }
    }

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
        System.out.println("Press enter to continue");
        input.nextLine();
        return false;
    }

    private static String send(String choice) throws Exception {
        return send(choice, null);
    }

    private static String send(String choice, String arg1) throws Exception {
        return send(choice, arg1, null);
    }

    private static String send(String choice, String arg1, String arg2) throws Exception {
        return service.incoming(choice, arg1, arg2, user);
    }

}
