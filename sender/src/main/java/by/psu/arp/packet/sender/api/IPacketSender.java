package by.psu.arp.packet.sender.api;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

/**
 * Packet sender interface.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public interface IPacketSender {

    /**
     * Sends a packet.
     *
     * @param packet packet to send
     */
    void send(Packet packet) throws PcapNativeException, NotOpenException;
}
