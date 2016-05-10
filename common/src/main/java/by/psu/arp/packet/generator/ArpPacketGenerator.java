package by.psu.arp.packet.generator;

import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.packet.ArpPacket.Builder;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Random;

import static org.pcap4j.util.MacAddress.SIZE_IN_BYTES;

/**
 * Packet generator utils.
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public final class ArpPacketGenerator {

    private static final Logger LOGGER = ArpLogger.getLogger();

    private static final int IPV4_ADDRESS_SIZE = 4;
    private static final Random RANDOM = new Random(System.currentTimeMillis());

    private final Builder builder;

    public ArpPacketGenerator() {
        builder = new Builder()
                .hardwareType(ArpHardwareType.ETHERNET)
                .protocolType(EtherType.IPV4)
                .hardwareAddrLength((byte) SIZE_IN_BYTES)
                .protocolAddrLength((byte) ByteArrays.INET4_ADDRESS_SIZE_IN_BYTES);
    }

    /**
     * Generates a random  arp-request packet.
     *
     * @return generated arp-request packet
     */
    public Packet generateRequestPacket() {
        builder.operation(ArpOperation.REQUEST);
        return generatePacket(MacAddress.ETHER_BROADCAST_ADDRESS);
    }

    /**
     * Generates a random  arp-response packet.
     *
     * @return generated arp-response packet
     */
    public Packet generateReplayPacket() {
        builder.operation(ArpOperation.REPLY);
        return generatePacket(generateMacAddress());
    }

    private Packet generatePacket(MacAddress dstMacAddress) {
        MacAddress srcMacAddress = generateMacAddress();
        builder
                .srcHardwareAddr(srcMacAddress)
                .srcProtocolAddr(generateInetAddress())
                .dstHardwareAddr(dstMacAddress)
                .dstProtocolAddr(generateInetAddress());
        return build(srcMacAddress, dstMacAddress);
    }

    private MacAddress generateMacAddress() {
        byte[] macBytes = new byte[SIZE_IN_BYTES];
        RANDOM.nextBytes(macBytes);
        return MacAddress.getByAddress(macBytes);
    }

    private InetAddress generateInetAddress() {
        byte[] addrBytes = new byte[IPV4_ADDRESS_SIZE];
        while (true) {
            RANDOM.nextBytes(addrBytes);
            try {
                return InetAddress.getByAddress(addrBytes);
            } catch (UnknownHostException ignored) {
            }
        }
    }

    private EthernetPacket build(MacAddress srcMacAddress, MacAddress dstMacAddress) {
        return new EthernetPacket.Builder()
                .srcAddr(srcMacAddress)
                .dstAddr(dstMacAddress)
                .type(EtherType.ARP)
                .payloadBuilder(builder)
                .paddingAtBuild(true)
                .build();
    }
}
