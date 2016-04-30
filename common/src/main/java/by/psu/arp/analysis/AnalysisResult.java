package by.psu.arp.analysis;

import by.psu.arp.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;

/**
 * Analysis result.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class AnalysisResult {

    private PacketInfo<? extends ArpPacket> packetInfo;
    private AnalysisResultType resultType;

    public AnalysisResult(PacketInfo<? extends ArpPacket> packetInfo, AnalysisResultType resultType) {
        this.packetInfo = packetInfo;
        this.resultType = resultType;
    }

    public PacketInfo<? extends ArpPacket> getPacketInfo() {
        return packetInfo;
    }

    public void setPacketInfo(PacketInfo<? extends ArpPacket> packetInfo) {
        this.packetInfo = packetInfo;
    }

    public AnalysisResultType getResultType() {
        return resultType;
    }

    public void setResultType(AnalysisResultType resultType) {
        this.resultType = resultType;
    }
}
