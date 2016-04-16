package by.psu.arp.analyzer.plain;

import by.psu.arp.model.analysis.AnalysisErrorResultHandler;
import by.psu.arp.model.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;

import java.util.NavigableSet;

/**
 * Plain packet info analyzer interface.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public interface IPlainAnalyzer {

    /**
     * Analyses packet info & adds error (if they exist) to result handler.
     *
     * @param packetInfo    packet info to analyze
     * @param packets       packets associated with this packet info
     * @param resultHandler result handler
     */
    void analyze(PacketInfo<? extends ArpPacket> packetInfo, NavigableSet<PacketInfo<ArpPacket>> packets,
                 AnalysisErrorResultHandler resultHandler);
}
