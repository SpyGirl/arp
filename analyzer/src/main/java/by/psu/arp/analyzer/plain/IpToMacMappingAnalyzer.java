package by.psu.arp.analyzer.plain;

import by.psu.arp.model.analysis.AnalysisErrorResultHandler;
import by.psu.arp.model.analysis.AnalysisResult;
import by.psu.arp.model.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;

import java.net.InetAddress;
import java.util.Collection;
import java.util.concurrent.ConcurrentSkipListSet;

import static by.psu.arp.model.analysis.AnalysisResultType.MULTIPLE_MAC_FOR_IP;
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
    public void analyze(PacketInfo<? extends ArpPacket> packetInfo, AnalysisErrorResultHandler resultHandler) {
        InetAddress sourceIpAddress = getSourceInetAddress(packetInfo);
        ConcurrentSkipListSet<PacketInfo<ArpPacket>> packetInfoList =
                getStorageInstance().getRequests(sourceIpAddress);
        internalAnalyze(packetInfo, packetInfoList, resultHandler);
        packetInfoList = getStorageInstance().getReplays(sourceIpAddress);
        internalAnalyze(packetInfo, packetInfoList, resultHandler);
        if (resultHandler.hasErrors()) {
            resultHandler.addError(new AnalysisResult(packetInfo, MULTIPLE_MAC_FOR_IP));
        }
    }

    private void internalAnalyze(PacketInfo<? extends ArpPacket> packetInfo,
                                 Collection<PacketInfo<ArpPacket>> packetInfoList,
                                 AnalysisErrorResultHandler resultHandler) {
        packetInfoList.stream()
                .filter(arpPacketInfo -> !getSourceMacAddress(packetInfo).equals(getSourceMacAddress(arpPacketInfo)))
                .forEach(arpPacketInfo -> {
                    resultHandler.addError(new AnalysisResult(arpPacketInfo, MULTIPLE_MAC_FOR_IP));
                });
    }


}
