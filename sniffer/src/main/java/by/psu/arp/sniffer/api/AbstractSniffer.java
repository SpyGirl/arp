package by.psu.arp.sniffer.api;

import by.psu.arp.listener.api.IPacketSniffer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;

/**
 * Abstract sensor.
 * <p>
 * Date: Mar 22, 2016
 * </p>
 */
public abstract class AbstractSniffer implements ISniffer {

    private final static int LOOP_ONCE = 1;

    private final PcapHandle handle;
    private final IPacketSniffer packetListener;

    /**
     * Constructor.
     *
     * @param handle pcap handle
     * @param packetListener packet listener
     */
    public AbstractSniffer(PcapHandle handle, IPacketSniffer packetListener) {
        this.handle = handle;
        this.packetListener = packetListener;
    }

    @Override
    public ArpPacket catchNextPacket() throws PcapNativeException, InterruptedException, NotOpenException {
        handle.loop(LOOP_ONCE, packetListener);
        return packetListener.getPacket();
    }

    @Override
    public void stop() throws NotOpenException {
        handle.breakLoop();
    }
}
