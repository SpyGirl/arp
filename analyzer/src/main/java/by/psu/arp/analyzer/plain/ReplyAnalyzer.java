package by.psu.arp.analyzer.plain;

import by.psu.arp.model.analysis.AnalysisErrorResultHandler;
import by.psu.arp.model.analysis.AnalysisResult;
import by.psu.arp.model.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.util.NavigableSet;

import static by.psu.arp.model.analysis.AnalysisResultType.REPLAY_TIMEOUT_EXPIRE;
import static by.psu.arp.model.analysis.AnalysisResultType.REPLAY_WITHOUT_REQUEST;
import static by.psu.arp.util.packet.PacketInfoUtils.getArpOperation;
import static by.psu.arp.util.packet.PacketInfoUtils.getTimeInMiliseconds;

/**
 * Reply analyzer.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class ReplyAnalyzer implements IPlainAnalyzer {

    private static final long REPLY_TIMEOUT = 500; // reply timeout in ms

    @Override
    public void analyze(PacketInfo<? extends ArpPacket> packetInfo, NavigableSet<PacketInfo<ArpPacket>> packets,
                        AnalysisErrorResultHandler resultHandler) {
        // Check operation type. Interested in REPLY type.
        if (getArpOperation(packetInfo).equals(ArpOperation.REPLY)) {
            if (packets == null) { // There were no requests for this IP address.
                resultHandler.addError(new AnalysisResult(packetInfo, REPLAY_WITHOUT_REQUEST));
            } else {
                // Check timeout.
                long timeDiff = getTimeInMiliseconds(packets.first()) - getTimeInMiliseconds(packetInfo);
                if (REPLY_TIMEOUT >= timeDiff) { // reply timeout expired
                    resultHandler.addError(new AnalysisResult(packetInfo, REPLAY_TIMEOUT_EXPIRE));
                }
            }
        }
    }
}
