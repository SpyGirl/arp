package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.analysis.AnalysisResult;
import by.psu.arp.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.util.MacAddress;

import java.util.Collection;
import java.util.concurrent.ConcurrentSkipListSet;

import static by.psu.arp.analysis.AnalysisResultType.SPAM_FROM_MAC;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;
import static by.psu.arp.util.packet.PacketInfoUtils.getSourceMacAddress;

/**
 * Spam analyzer.
 * <p>
 * Date: Apr 17, 2016
 * </p>
 */
public class SpamAnalyzer implements IPlainAnalyzer {

    private static final long PACKET_TRANSFER_TIME_BOUNDS = 1000; // time in ms
    private static final long ACCEPTABLE_NUMBER_OF_PACKETS = 50;

    @Override
    public AnalysisErrorResultHandler analyze(PacketInfo<? extends ArpPacket> packetInfo) {
        AnalysisErrorResultHandler resultHandler = new AnalysisErrorResultHandler();
        long lowerTimeBounds = System.currentTimeMillis() - PACKET_TRANSFER_TIME_BOUNDS;
        MacAddress sourceMacAddress = getSourceMacAddress(packetInfo);
        ConcurrentSkipListSet<PacketInfo<ArpPacket>> packets = getStorageInstance().getRequests(sourceMacAddress);
        long packetsCount = countPackets(packetInfo, packets, lowerTimeBounds);
        packets = getStorageInstance().getReplays(sourceMacAddress);
        packetsCount += countPackets(packetInfo, packets, lowerTimeBounds);
        if (packetsCount > ACCEPTABLE_NUMBER_OF_PACKETS) {
            resultHandler.addError(new AnalysisResult(packetInfo, SPAM_FROM_MAC));
        }
        return resultHandler;
    }

    private long countPackets(PacketInfo<? extends ArpPacket> packetInfo, Collection<PacketInfo<ArpPacket>> packets,
                              long lowerTimeBounds) {
        if (packets == null) {
            return 0;
        }
        return packets.stream()
                .filter(arpPacketInfo ->
                        getSourceMacAddress(packetInfo).equals(getSourceMacAddress(arpPacketInfo)) &&
                                arpPacketInfo.getDateTime().getTime() > lowerTimeBounds
                )
                .count();
    }

}
