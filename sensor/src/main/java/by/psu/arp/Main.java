package by.psu.arp;

import by.psu.arp.launcher.impl.SensorLauncher;
import by.psu.arp.util.logging.ArpLogger;
import org.slf4j.Logger;

import java.util.Scanner;

/**
 * Date: Май 10, 2016
 */
public class Main {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final String STOP_COMMAND = "stop";

    public static void main(String[] args) {
        SensorLauncher sensorLauncher = new SensorLauncher();
        sensorLauncher.launch();

        Scanner cin = new Scanner(System.in);
        String stop = "";
        while (!stop.equals(STOP_COMMAND)) {
            stop = cin.nextLine();
        }

        sensorLauncher.stop();
        LOGGER.info("Application has been stopped.");
    }
}
