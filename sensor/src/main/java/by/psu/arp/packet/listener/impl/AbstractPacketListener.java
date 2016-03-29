package by.psu.arp.packet.listener.impl;

import by.psu.arp.packet.listener.api.IPacketListener;
import org.pcap4j.packet.ArpPacket;

/**
 * Abstract packet listener.
 * <p>
 * Date: Mar 22, 2016
 * </p>
 */
public abstract class AbstractPacketListener implements IPacketListener {

    /**
     * Caught packet.
     */
    protected ArpPacket packet;


    public ArpPacket getPacket() {
        return packet;
    }
}
