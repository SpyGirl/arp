package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.analysis.AnalysisResult;
import by.psu.arp.packet.PacketInfo;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;

import java.util.concurrent.ConcurrentSkipListSet;

import static by.psu.arp.analysis.AnalysisResultType.REPLAY_TIMEOUT_EXPIRE;
import static by.psu.arp.analysis.AnalysisResultType.REPLAY_WITHOUT_REQUEST;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;
import static by.psu.arp.util.packet.PacketInfoUtils.*;

/**
 * Reply analyzer.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class ReplyAnalyzer implements IPlainAnalyzer {

    private static final long REPLY_TIMEOUT = 500; // reply timeout in ms

    @Override
    public AnalysisErrorResultHandler analyze(PacketInfo<? extends ArpPacket> packetInfo) {
        AnalysisErrorResultHandler resultHandler = new AnalysisErrorResultHandler();
        // Check operation type. Interested in REPLY type.
        if (getArpOperation(packetInfo).equals(ArpOperation.REPLY)) {
            ConcurrentSkipListSet<PacketInfo<ArpPacket>> packets =
                    getStorageInstance().getRequests(getSourceInetAddress(packetInfo));
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
        return resultHandler;
    }
}
