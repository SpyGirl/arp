package by.psu.arp.executor;

import by.psu.arp.model.packet.PacketInfo;
import by.psu.arp.storage.PacketInfoStorage;
import by.psu.arp.util.logging.ArpLogger;
import by.psu.arp.packet.sensor.api.ISensor;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;
import org.slf4j.Logger;

/**
 * Sender executor.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class SensorExecutor implements Executor {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final String STOP_EXECUTION_ERROR = "Error occurred while trying to stop catching packets.";
    private static final String CATCH_EXECUTION_ERROR = "Error occurred while catching packets.";

    private final PacketInfoStorage storage = PacketInfoStorage.getStorageInstance();

    private ISensor sensor;
    private volatile boolean isStopped;

    public SensorExecutor(ISensor sensor) {
        this.sensor = sensor;
    }

    @Override
    public void stop() {
        isStopped = true;
        try {
            sensor.stop();
        } catch (NotOpenException e) {
            LOGGER.error(STOP_EXECUTION_ERROR, e);
        }
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                if (isStopped) {
                    break;
                }
                ArpPacket arpPacket = sensor.catchNextPacket();
                storage.put(new PacketInfo<>(arpPacket));
                LOGGER.info("Caught packet:\n{}", arpPacket);
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                LOGGER.error(CATCH_EXECUTION_ERROR, e);
                break;
            }
        }
    }
}
