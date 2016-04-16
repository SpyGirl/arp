package by.psu.arp.packet.listener.api;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.ArpPacket;

/**
 * Packet listener interface.
 * <p>
 * Date: Mar 22, 2016
 * </p>
 */
public interface IPacketListener extends PacketListener {

    /**
     * Gets caught packet.
     *
     * @return packet
     */
    ArpPacket getPacket();
}
