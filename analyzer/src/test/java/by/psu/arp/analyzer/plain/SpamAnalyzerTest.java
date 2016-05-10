package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.packet.PacketInfo;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.util.MacAddress;

import java.util.Date;

import static by.psu.arp.analysis.AnalysisResultType.SPAM_FROM_MAC;
import static by.psu.arp.analyzer.plain.util.PacketUtils.*;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;
import static org.junit.Assert.assertEquals;

/**
 * Tests for {@link SpamAnalyzer}.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public class SpamAnalyzerTest {

    private SpamAnalyzer analyzer = new SpamAnalyzer();

    @Test
    public void mustProduceSpamFromMacResult() {
        MacAddress srcMacAddr = generateMacAddress();
        ArpPacket packet = generateReplyArpPacket(srcMacAddr, generateInetAddress(),
                generateMacAddress(), generateInetAddress());
        long timeMillis = System.currentTimeMillis();
        for (int i = 0; i < 51; i++) {
            PacketInfo<ArpPacket> packetInfo = new PacketInfo<>(packet);
            packetInfo.setDateTime(new Date(timeMillis + i * 1000));
            getStorageInstance().put(packetInfo);
        }
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(new PacketInfo<>(packet));
        assertEquals(1, resultHandler.getAnalysisResults().size());
        assertEquals(SPAM_FROM_MAC, resultHandler.getAnalysisResults().get(0).getResultType());
    }

    @Test
    public void mustProducePositiveResult() {
        for (int i = 0; i < 51; i++) {
            ArpPacket packet = generateReplyArpPacket(generateMacAddress(), generateInetAddress(),
                    generateMacAddress(), generateInetAddress());
            PacketInfo<ArpPacket> packetInfo = new PacketInfo<>(packet);
            getStorageInstance().put(packetInfo);
        }
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(new PacketInfo<>(
                generateReplyArpPacket(generateMacAddress(), generateInetAddress(), generateMacAddress(),
                        generateInetAddress())
        ));
        assertEquals(0, resultHandler.getAnalysisResults().size());
    }
}
