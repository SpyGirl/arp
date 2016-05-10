package by.psu.arp.executor;

import by.psu.arp.analyzer.AnalyzerContainer;
import by.psu.arp.packet.PacketInfo;
import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.packet.ArpPacket;
import org.slf4j.Logger;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;

/**
 * .
 * <p>
 * Created: 07/05/16
 * </p>
 */
public class AnalyzerExecutor implements IExecutor {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final ExecutorService EXECUTOR_SERVICE = Executors.newFixedThreadPool(100);

    private volatile boolean isStopped;

    @Override
    public void stop() {
        isStopped = true;
        LOGGER.info("Stop signal for analyzer.");
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            if (isStopped) {
                break;
            }
            PacketInfo<ArpPacket> packetInfo = getStorageInstance().pollPacket();
            if (packetInfo != null) {
                EXECUTOR_SERVICE.execute(() -> AnalyzerContainer.analyze(packetInfo));
            }
        }
        LOGGER.info("Analyzer is stopped.");
    }
}
