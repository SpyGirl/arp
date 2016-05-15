package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.analysis.AnalysisResult;
import by.psu.arp.packet.PacketInfo;
import by.psu.arp.settings.SettingsHolder;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;

import static by.psu.arp.analysis.AnalysisResultType.MULTIPLE_IP_FOR_MAC;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;
import static by.psu.arp.util.packet.PacketInfoUtils.*;

/**
 * Mac to ip address mapping analyzer.
 * Checks that one mac address is mapped to one inet address only.
 * <p>
 * Date: Apr 08, 2016
 * </p>
 */
public class MacToIpMappingAnalyzer implements IPlainAnalyzer {

    private static final Set<String> EXCLUDE_HOSTS;

    static {
        String hosts = "";
        try {
            hosts = SettingsHolder.getProperty("analyzer.excludeHosts");
        } catch (Exception ignored) {
        }
        EXCLUDE_HOSTS = new TreeSet<>(Arrays.asList(hosts.split(";")));
    }

    @Override
    public AnalysisErrorResultHandler analyze(PacketInfo<? extends ArpPacket> packetInfo) {
        InetAddress destAddress = getDestinationInetAddress(packetInfo);
        if (EXCLUDE_HOSTS.contains(destAddress.getHostAddress())) {
            return new AnalysisErrorResultHandler();
        }
        MacAddress sourceMacAddress = getSourceMacAddress(packetInfo);
        ConcurrentSkipListSet<PacketInfo<ArpPacket>> packetInfoList =
                getStorageInstance().getRequests(sourceMacAddress);
        AnalysisErrorResultHandler resultHandler = internalAnalyze(packetInfo, packetInfoList);
        packetInfoList = getStorageInstance().getReplays(sourceMacAddress);
        resultHandler.addErrors(internalAnalyze(packetInfo, packetInfoList).getAnalysisResults());
        if (resultHandler.hasErrors()) {
            resultHandler.addError(new AnalysisResult(packetInfo, MULTIPLE_IP_FOR_MAC));
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
                .filter(arpPacketInfo -> !getSourceInetAddress(packetInfo).equals(getSourceInetAddress(arpPacketInfo)))
                .forEach(arpPacketInfo ->
                        resultHandler.addError(new AnalysisResult(arpPacketInfo, MULTIPLE_IP_FOR_MAC)));
        return resultHandler;
    }
}
