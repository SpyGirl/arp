package by.psu.arp.util.packet;

import by.psu.arp.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;

/**
 * PacketInfo utils.
 * <p>
 * Date: Apr 05, 2016
 * </p>
 */
public final class PacketInfoUtils {

    private PacketInfoUtils() {
        throw new UnsupportedOperationException("This constructor must never be called.");
    }

    public static InetAddress getSourceInetAddress(PacketInfo<? extends ArpPacket> packetInfo) {
        return packetInfo.getPacket().getHeader().getSrcProtocolAddr();
    }

    public static InetAddress getDestinationInetAddress(PacketInfo<? extends ArpPacket> packetInfo) {
        return packetInfo.getPacket().getHeader().getDstProtocolAddr();
    }

    public static ArpOperation getArpOperation(PacketInfo<? extends ArpPacket> packetInfo) {
        return packetInfo.getPacket().getHeader().getOperation();
    }

    public static MacAddress getSourceMacAddress(PacketInfo<? extends ArpPacket> packetInfo) {
        return packetInfo.getPacket().getHeader().getSrcHardwareAddr();
    }

    public static MacAddress getDestinationMacAddress(PacketInfo<? extends ArpPacket> packetInfo) {
        return packetInfo.getPacket().getHeader().getDstHardwareAddr();
    }

    public static long getTimeInMiliseconds(PacketInfo<? extends ArpPacket> packetInfo) {
        return packetInfo.getDateTime().getTime();
    }
}
