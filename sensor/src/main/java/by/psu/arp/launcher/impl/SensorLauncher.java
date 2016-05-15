package by.psu.arp.launcher.impl;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.launcher.api.IAnalyzerLauncher;
import by.psu.arp.launcher.api.ILauncher;
import by.psu.arp.net.Client;
import by.psu.arp.settings.SettingsHolder;
import by.psu.arp.util.logging.ArpLogger;
import org.slf4j.Logger;

import java.io.FileWriter;
import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;

/**
 * Date: Май 10, 2016
 */
public class SensorLauncher implements ILauncher {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final int STORAGE_CLEAN_PERIOD;
    private static final int SERVER_NOTIFIER_PERIOD;

    private IAnalyzerLauncher analyzer = new AnalyzerLauncher();
    private ILauncher sniffer = new SnifferLauncher();
    private ScheduledExecutorService storageCleaner = new ScheduledThreadPoolExecutor(1);
    private ScheduledExecutorService serverNotifier = new ScheduledThreadPoolExecutor(1);
    private Client client;

    static {
        STORAGE_CLEAN_PERIOD = Integer.parseInt(SettingsHolder.getProperty("sensor.storageCleanPeriod"));
        SERVER_NOTIFIER_PERIOD = Integer.parseInt(SettingsHolder.getProperty("sensor.serverNotifierPeriod"));
    }

    @Override
    public void launch() {
        String serverHost = SettingsHolder.getProperty("client.serverHost");
        int serverPort = Integer.parseInt(SettingsHolder.getProperty("client.serverPort"));
        client = new Client(serverHost, serverPort);
        analyzer.launch();
        sniffer.launch();
        storageCleaner.scheduleWithFixedDelay(() -> {
            Date date = new Date();
            int count = getStorageInstance().cleanUpToDateTime(date);
            LOGGER.info("{} packets were cleaned up during storage cleaning at {}", count, date);
        }, STORAGE_CLEAN_PERIOD, STORAGE_CLEAN_PERIOD, TimeUnit.MINUTES);
        serverNotifier.scheduleAtFixedRate(() -> {
            Collection<AnalysisErrorResultHandler> results = analyzer.getResults();
            if (results.size() > 0) {
                LOGGER.info("Notify the server.");
                try {
                    client.send(results);
                } catch (IOException e) {
                    String path = SettingsHolder.getProperty("sensor.localResultsFile");
                    LOGGER.info("Notification operation failed, write to local file [{}]", path);
                    try (FileWriter writer = new FileWriter(path, true)) {
                        writer.write(results.toString());
                    } catch (IOException e1) {
                        LOGGER.error("I/O error while appending info to the file.", e1);
                    }
                }
            }
        }, SERVER_NOTIFIER_PERIOD, SERVER_NOTIFIER_PERIOD, TimeUnit.MINUTES);
    }

    @Override
    public void stop() {
        storageCleaner.shutdown();
        serverNotifier.shutdown();
        sniffer.stop();
        analyzer.stop();
    }
}
