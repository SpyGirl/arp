package by.psu.arp.listener.api;

import org.pcap4j.packet.ArpPacket;

/**
 * Abstract packet listener.
 * <p>
 * Date: Mar 22, 2016
 * </p>
 */
public abstract class AbstractPacketSniffer implements IPacketSniffer {

    /**
     * Caught packet.
     */
    protected ArpPacket packet;


    public ArpPacket getPacket() {
        return packet;
    }
}
