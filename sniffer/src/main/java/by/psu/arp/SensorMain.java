package by.psu.arp;

import by.psu.arp.launcher.SensorLauncher;

import java.util.Scanner;

/**
 * Date: Mar 19, 2016
 */
public class SensorMain {

    public static void main(String[] args) throws InterruptedException {

        SensorLauncher launcher = new SensorLauncher();
        launcher.launch();

        Scanner scanner = new Scanner(System.in);
        while (scanner.hasNext()) {
            String command = scanner.nextLine();
            if ("stop".equalsIgnoreCase(command)) {
                launcher.stop();
                break;
            }
        }
    }
}
