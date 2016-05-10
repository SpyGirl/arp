package by.psu.arp.executor.impl;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.analyzer.AnalyzerContainer;
import by.psu.arp.executor.api.IAnalyzerExecutor;
import by.psu.arp.packet.PacketInfo;
import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.packet.ArpPacket;
import org.slf4j.Logger;

import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;

/**
 * .
 * <p>
 * Created: 07/05/16
 * </p>
 */
public class AnalyzerExecutor implements IAnalyzerExecutor {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final ExecutorService EXECUTOR_SERVICE = Executors.newFixedThreadPool(100);

    private ConcurrentSkipListSet<AnalysisErrorResultHandler> results = new ConcurrentSkipListSet<>();
    private volatile boolean isStopped;

    @Override
    public AnalysisErrorResultHandler getResult() {
        return results.pollFirst();
    }

    @Override
    public void stop() {
        LOGGER.info("Stop signal for analyzer executor.");
        EXECUTOR_SERVICE.shutdownNow();
        isStopped = true;
    }

    @Override
    public void run() {
        LOGGER.info("Analyzer executor has been started.");
        while (!Thread.currentThread().isInterrupted()) {
            if (isStopped) {
                break;
            }
            PacketInfo<ArpPacket> packetInfo = getStorageInstance().pollPacket();
            if (packetInfo != null) {
               EXECUTOR_SERVICE.execute(() -> {
                    AnalysisErrorResultHandler resultHandler = AnalyzerContainer.analyze(packetInfo);
                    results.add(resultHandler);
               });
            }
        }
        LOGGER.info("Analyzer executor has been stopped.");
    }
}
