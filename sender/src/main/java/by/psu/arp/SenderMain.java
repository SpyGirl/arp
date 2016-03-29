package by.psu.arp;

import by.psu.arp.launcher.SenderLauncher;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.util.Scanner;

/**
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class SenderMain {

    public static void main(String[] args) throws NotOpenException, PcapNativeException, InterruptedException {

        SenderLauncher launcher = new SenderLauncher();
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
