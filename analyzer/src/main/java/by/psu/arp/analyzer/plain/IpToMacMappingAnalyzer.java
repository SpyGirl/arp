package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.analysis.AnalysisResult;
import by.psu.arp.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;

import java.net.InetAddress;
import java.util.Collection;
import java.util.concurrent.ConcurrentSkipListSet;

import static by.psu.arp.analysis.AnalysisResultType.MULTIPLE_MAC_FOR_IP;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;
import static by.psu.arp.util.packet.PacketInfoUtils.getSourceInetAddress;
import static by.psu.arp.util.packet.PacketInfoUtils.getSourceMacAddress;

/**
 * Inet address to mac mapping analyzer.
 * Checks that one inet address is mapped to one mac only.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class IpToMacMappingAnalyzer implements IPlainAnalyzer {

    @Override
    public AnalysisErrorResultHandler analyze(PacketInfo<? extends ArpPacket> packetInfo) {
        InetAddress sourceIpAddress = getSourceInetAddress(packetInfo);
        ConcurrentSkipListSet<PacketInfo<ArpPacket>> packetInfoList = getStorageInstance().getRequests(sourceIpAddress);
        AnalysisErrorResultHandler resultHandler = internalAnalyze(packetInfo, packetInfoList);
        packetInfoList = getStorageInstance().getReplays(sourceIpAddress);
        resultHandler.addErrors(internalAnalyze(packetInfo, packetInfoList).getAnalysisResults());
        if (resultHandler.hasErrors()) {
            resultHandler.addError(new AnalysisResult(packetInfo, MULTIPLE_MAC_FOR_IP));
        }
        return resultHandler;
    }

    private AnalysisErrorResultHandler internalAnalyze(PacketInfo<? extends ArpPacket> packetInfo,
                                                       Collection<PacketInfo<ArpPacket>> packetInfoList) {
        AnalysisErrorResultHandler resultHandler = new AnalysisErrorResultHandler();
        if (packetInfoList == null) {
            return resultHandler;
        }
        packetInfoList.stream()
                .filter(arpPacketInfo -> !getSourceMacAddress(packetInfo).equals(getSourceMacAddress(arpPacketInfo)))
                .forEach(arpPacketInfo ->
                        resultHandler.addError(new AnalysisResult(arpPacketInfo, MULTIPLE_MAC_FOR_IP)));
        return resultHandler;
    }


}
