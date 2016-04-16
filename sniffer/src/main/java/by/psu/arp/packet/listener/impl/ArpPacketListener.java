package by.psu.arp.packet.listener.impl;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

/**
 * Arp packet listener.
 * <p>
 * Date: Mar 22, 2016
 * </p>
 */
public class ArpPacketListener extends AbstractPacketListener {

    private static final Class<ArpPacket> ARP_PACKET_CLASS = ArpPacket.class;

    @Override
    public void gotPacket(Packet packet) {
        if (packet.contains(ARP_PACKET_CLASS)) {
            this.packet = packet.get(ARP_PACKET_CLASS);
        }
    }
}
