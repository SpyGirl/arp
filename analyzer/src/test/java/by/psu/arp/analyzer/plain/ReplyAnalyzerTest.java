package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.packet.PacketInfo;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket;

import java.net.InetAddress;

import static by.psu.arp.analysis.AnalysisResultType.REPLAY_WITHOUT_REQUEST;
import static by.psu.arp.analyzer.plain.util.PacketUtils.*;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;
import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link ReplyAnalyzer}.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public class ReplyAnalyzerTest {

    private ReplyAnalyzer analyzer = new ReplyAnalyzer();

    @Test
    public void mustProduceReplayWithoutRequestResult() {
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(
                new PacketInfo<>(generateReplyArpPacket(generateMacAddress(),
                        generateInetAddress(), generateMacAddress(), generateInetAddress())));
        assertEquals(1, resultHandler.getAnalysisResults().size());
        assertEquals(REPLAY_WITHOUT_REQUEST, resultHandler.getAnalysisResults().get(0).getResultType());
    }

    @Test
    public void mustProduceReplyTimeoutExpireResult() throws InterruptedException {
        InetAddress srcAddr = generateInetAddress();
        InetAddress dstAddr = generateInetAddress();
        PacketInfo<ArpPacket> packetInfo = new PacketInfo<>(generateRequestArpPacket(generateMacAddress(), srcAddr,
                generateMacAddress(), dstAddr));
        getStorageInstance().put(packetInfo);
        Thread.sleep(2001);
        packetInfo = new PacketInfo<>(generateReplyArpPacket(generateMacAddress(), dstAddr, generateMacAddress(), srcAddr));
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(packetInfo);
        assertEquals(1, resultHandler.getAnalysisResults().size());
    }

    @Test
    public void mustProducePositiveResult() {
        InetAddress srcAddr = generateInetAddress();
        InetAddress dstAddr = generateInetAddress();
        PacketInfo<ArpPacket> packetInfo = new PacketInfo<>(generateRequestArpPacket(generateMacAddress(), srcAddr,
                generateMacAddress(), dstAddr));
        getStorageInstance().put(packetInfo);
        packetInfo = new PacketInfo<>(generateReplyArpPacket(generateMacAddress(), dstAddr, generateMacAddress(), srcAddr));
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(packetInfo);
        assertEquals(0, resultHandler.getAnalysisResults().size());
    }

}
