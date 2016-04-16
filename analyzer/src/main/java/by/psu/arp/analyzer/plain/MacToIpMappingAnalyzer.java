package by.psu.arp.analyzer.plain;

import by.psu.arp.model.analysis.AnalysisErrorResultHandler;
import by.psu.arp.model.analysis.AnalysisResult;
import by.psu.arp.model.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;

import java.util.Collection;
import java.util.NavigableSet;

import static by.psu.arp.model.analysis.AnalysisResultType.MULTIPLE_IP_FOR_MAC;
import static by.psu.arp.util.packet.PacketInfoUtils.getSourceInetAddress;

/**
 * Mac to ip address mapping analyzer.
 * Checks that one mac address is mapped to one inet address only.
 * <p>
 * Date: Apr 08, 2016
 * </p>
 */
public class MacToIpMappingAnalyzer implements IPlainAnalyzer {

    @Override
    public void analyze(PacketInfo<? extends ArpPacket> packetInfo, NavigableSet<PacketInfo<ArpPacket>> packets,
                        AnalysisErrorResultHandler resultHandler) {
        innerAnalyze(packetInfo, packets, resultHandler);
        if (resultHandler.hasErrors()) {
            resultHandler.addError(new AnalysisResult(packetInfo, MULTIPLE_IP_FOR_MAC));
        }
    }

    private void innerAnalyze(PacketInfo<? extends ArpPacket> packetInfo,
                              Collection<PacketInfo<ArpPacket>> packetInfoList,
                              AnalysisErrorResultHandler resultHandler) {
        packetInfoList.stream()
                .filter(arpPacketInfo -> !getSourceInetAddress(packetInfo).equals(getSourceInetAddress(arpPacketInfo)))
                .forEach(arpPacketInfo -> {
                    resultHandler.addError(new AnalysisResult(arpPacketInfo, MULTIPLE_IP_FOR_MAC));
                });
    }
}
