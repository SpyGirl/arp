package by.psu.arp.launcher.impl;

import by.psu.arp.launcher.api.IAnalyzerLauncher;
import by.psu.arp.launcher.api.ILauncher;
import by.psu.arp.util.logging.ArpLogger;
import org.slf4j.Logger;

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

    private IAnalyzerLauncher analyzer = new AnalyzerLauncher();
    private ILauncher sniffer = new SnifferLauncher();
    private ScheduledExecutorService storageCleaner = new ScheduledThreadPoolExecutor(1);

    @Override
    public void launch() {
        analyzer.launch();
        sniffer.launch();
        storageCleaner.scheduleWithFixedDelay((Runnable) () -> {
            Date date = new Date();
            int count = getStorageInstance().cleanUpToDateTime(date);
            LOGGER.info("{} packets were cleaned up during storage cleaning at {}", count, date);
        }, 30, 30, TimeUnit.MINUTES);
    }

    @Override
    public void stop() {
        storageCleaner.shutdown();
        sniffer.stop();
        analyzer.stop();
    }
}
