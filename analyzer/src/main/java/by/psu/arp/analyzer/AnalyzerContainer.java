package by.psu.arp.analyzer;

import by.psu.arp.analyzer.plain.*;
import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.packet.PacketInfo;
import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.packet.ArpPacket;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.*;

/**
 * Analyzer container.
 * <p>
 * Date: Apr 30, 2016
 * </p>
 */
public abstract class AnalyzerContainer {

    private static final Logger LOGGER = ArpLogger.getLogger();

    private static final int ANALYZERS_COUNT = 4;

    private static final List<IPlainAnalyzer> analyzers = Arrays.asList(
            new ReplyAnalyzer(),
            new IpToMacMappingAnalyzer(),
            new MacToIpMappingAnalyzer(),
            new SpamAnalyzer()
    );

    public static AnalysisErrorResultHandler analyze(PacketInfo<ArpPacket> packetInfo) {
        ExecutorService executorService = Executors.newFixedThreadPool(4);
        List<FutureTask<AnalysisErrorResultHandler>> tasks = new ArrayList<>(ANALYZERS_COUNT);
        analyzers.stream().forEach(analyzer -> {
            FutureTask<AnalysisErrorResultHandler> task = new FutureTask<>(new CallableAnalyzer(analyzer, packetInfo));
            tasks.add(task);
            executorService.execute(task);
        });
        AnalysisErrorResultHandler resultHandler = new AnalysisErrorResultHandler();
        while(tasks.size() > 0) {
            Iterator<FutureTask<AnalysisErrorResultHandler>> taskIterator = tasks.iterator();
            while (taskIterator.hasNext()) {
                FutureTask<AnalysisErrorResultHandler> task = taskIterator.next();
                if (task.isDone()) {
                    try {
                        resultHandler.addErrors(task.get().getAnalysisResults());
                    } catch (InterruptedException | ExecutionException e) {
                        LOGGER.error("Error while getting result of analyzer.", e);
                    }
                    taskIterator.remove();
                }
            }
        }
        return resultHandler;
    }

    private static class CallableAnalyzer implements Callable<AnalysisErrorResultHandler> {

        private IPlainAnalyzer analyzer;
        private PacketInfo<ArpPacket> packetInfo;

        CallableAnalyzer(IPlainAnalyzer analyzer, PacketInfo<ArpPacket> packetInfo) {
            this.analyzer = analyzer;
            this.packetInfo = packetInfo;
        }

        @Override
        public AnalysisErrorResultHandler call() throws Exception {
            return analyzer.analyze(packetInfo);
        }
    }
}
