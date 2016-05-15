package by.psu.arp.executor.impl;

import by.psu.arp.executor.IExecutor;
import by.psu.arp.packet.PacketInfo;
import by.psu.arp.sniffer.api.ISniffer;
import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;
import org.slf4j.Logger;

import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;

/**
 * Sender executor.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class SnifferExecutor implements IExecutor {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final String STOP_EXECUTION_ERROR = "Error occurred while trying to stop catching packets.";
    private static final String CATCH_EXECUTION_ERROR = "Error occurred while catching packets.";

    private ISniffer sniffer;
    private volatile boolean isStopped;

    public SnifferExecutor(ISniffer sniffer) {
        this.sniffer = sniffer;
    }

    @Override
    public void stop() {
        LOGGER.info("Stop signal for sniffer executor.");
        isStopped = true;
        try {
            sniffer.stop();
        } catch (NotOpenException e) {
            LOGGER.error(STOP_EXECUTION_ERROR, e);
        }
    }

    @Override
    public void run() {
        LOGGER.info("Sniffer executor has been started.");
        while (!Thread.currentThread().isInterrupted()) {
            try {
                if (isStopped) {
                    break;
                }
                ArpPacket arpPacket = sniffer.catchNextPacket();
                getStorageInstance().put(new PacketInfo<>(arpPacket));
                LOGGER.info("Caught packet:\n{}", arpPacket);
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                LOGGER.error(CATCH_EXECUTION_ERROR, e);
                break;
            }
        }
        LOGGER.info("Sniffer executor has been stopped.");
    }
}
