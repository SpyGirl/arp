package by.psu.arp.analyzer.plain.util;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

import static org.pcap4j.util.MacAddress.SIZE_IN_BYTES;

/**
 * Packet utils.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public final class PacketUtils {

    private static final int IPV4_ADDRESS_SIZE = 4;
    private static final Random RANDOM = new Random(System.currentTimeMillis());

    public PacketUtils() {
    }

    public static ArpPacket generateRequestArpPacket(MacAddress srcHardwareAddr, InetAddress srcProtocolAddr,
                                               MacAddress dstHardwareAddr, InetAddress dstProtocolAddr) {
        return createBuiler(srcHardwareAddr, srcProtocolAddr, dstHardwareAddr, dstProtocolAddr)
                .operation(ArpOperation.REQUEST)
                .build();
    }

    public static ArpPacket generateReplyArpPacket(MacAddress srcHardwareAddr, InetAddress srcProtocolAddr,
                                             MacAddress dstHardwareAddr, InetAddress dstProtocolAddr) {
        return createBuiler(srcHardwareAddr, srcProtocolAddr, dstHardwareAddr, dstProtocolAddr)
                .operation(ArpOperation.REPLY)
                .build();
    }

    private static ArpPacket.Builder createBuiler(MacAddress srcHardwareAddr, InetAddress srcProtocolAddr,
                                           MacAddress dstHardwareAddr, InetAddress dstProtocolAddr) {
        return new ArpPacket.Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES)
                .srcHardwareAddr(srcHardwareAddr)
                .srcProtocolAddr(srcProtocolAddr)
                .dstHardwareAddr(dstHardwareAddr)
                .dstProtocolAddr(dstProtocolAddr);
    }

    public static MacAddress generateMacAddress() {
        byte[] macBytes = new byte[SIZE_IN_BYTES];
        RANDOM.nextBytes(macBytes);
        return MacAddress.getByAddress(macBytes);
    }

    public static InetAddress generateInetAddress() {
        byte[] addrBytes = new byte[IPV4_ADDRESS_SIZE];
        while (true) {
            RANDOM.nextBytes(addrBytes);
            try {
                return InetAddress.getByAddress(addrBytes);
            } catch (UnknownHostException ignored) {
            }
        }
    }
}
