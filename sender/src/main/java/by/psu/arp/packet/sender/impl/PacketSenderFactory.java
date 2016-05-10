package by.psu.arp.packet.sender.impl;

import by.psu.arp.packet.sender.api.IPacketSender;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import static org.pcap4j.core.PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

/**
 * Packet sender factory.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class PacketSenderFactory {

    private static final int SNAPSHOT_LENGTH = 65536;
    private static final int READ_TIMEOUT = 20;

    private PacketSenderFactory() {
        throw new UnsupportedOperationException("This object must never be created.");
    }

    public static IPacketSender create(PcapNetworkInterface networkInterface) throws
            PcapNativeException {
        PcapHandle handle = networkInterface.openLive(SNAPSHOT_LENGTH, PROMISCUOUS, READ_TIMEOUT);
        return new PacketSender(handle);
    }
}
