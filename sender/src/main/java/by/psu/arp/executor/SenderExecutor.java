package by.psu.arp.executor;

import by.psu.arp.util.logging.ArpLogger;
import by.psu.arp.packet.generator.ArpPacketGenerator;
import by.psu.arp.packet.sender.api.IPacketSender;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.slf4j.Logger;

/**
 * Sender executor.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class SenderExecutor implements Executor {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final String SEND_EXECUTION_ERROR = "Error occurred while sending ARP packets.";

    private ThreadLocal<ArpPacketGenerator> packetGenerator;
    private IPacketSender packetSender;
    private int timeOut;
    private volatile boolean isStopped;

    public SenderExecutor(IPacketSender packetSender, int timeOut) {
        this.packetSender = packetSender;
        this.timeOut = timeOut;
        packetGenerator = new InheritableThreadLocal<>();
        packetGenerator.set(new ArpPacketGenerator());
    }

    @Override
    public void stop() {
        isStopped = true;
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                try {
                    Thread.sleep(timeOut);
                } catch (InterruptedException e) {
                    LOGGER.error("Thread is interrupted.", e);
                    isStopped = true;
                }
                if (isStopped) {
                    break;
                }
                packetSender.send(packetGenerator.get().generateRequestPacket());
                packetSender.send(packetGenerator.get().generateReplayPacket());
            } catch (PcapNativeException | NotOpenException e) {
                LOGGER.error(SEND_EXECUTION_ERROR, e);
                break;
            }
        }
    }
}
