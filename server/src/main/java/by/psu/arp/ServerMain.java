package by.psu.arp;

import by.psu.arp.net.Server;
import by.psu.arp.settings.SettingsHolder;

import java.util.Scanner;

/**
 * Date: Май 14, 2016
 */
public class ServerMain {

    private static final String RESOURCE_PROPS = "server.properties";

    public static void main(String[] args) {
        SettingsHolder.loadSettings(RESOURCE_PROPS);
        int port = Integer.parseInt(SettingsHolder.getProperty("server.port"));
        int maxClientsNumber = Integer.parseInt(SettingsHolder.getProperty("server.maxClientsNumber"));
        Server server = new Server(port, maxClientsNumber);
        server.start();
        Scanner cin = new Scanner(System.in);
        cin.nextLine();
        server.shutdown();
    }
}
