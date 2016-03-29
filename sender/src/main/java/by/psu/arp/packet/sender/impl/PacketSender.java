package by.psu.arp.packet.sender.impl;

import by.psu.arp.packet.sender.api.IPacketSender;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.Packet;

/**
 * Packet sender implementation.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class PacketSender implements IPacketSender {

    private PcapHandle handle;

    protected PacketSender(PcapHandle handle) {
        this.handle = handle;
    }

    @Override
    public void send(Packet packet) throws PcapNativeException, NotOpenException {
        handle.sendPacket(packet);
    }
}
