package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.packet.PacketInfo;
import org.junit.Assert;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.util.MacAddress;

import static by.psu.arp.analyzer.plain.util.PacketUtils.*;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;

/**
 * Tests for {@link MacToIpMappingAnalyzer}.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public class MacToIpMappingAnalyzerTest {

    private MacToIpMappingAnalyzer analyzer = new MacToIpMappingAnalyzer();

    @Test
    public void mustProduceMultipleMacForIpResult() {
        MacAddress srcMacAddr = generateMacAddress();
        ArpPacket packet = generateReplyArpPacket(srcMacAddr, generateInetAddress(),
                generateMacAddress(), generateInetAddress());
        getStorageInstance().put(new PacketInfo<>(packet));
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(new PacketInfo<>(generateReplyArpPacket(
                srcMacAddr, generateInetAddress(), generateMacAddress(), generateInetAddress())));
        Assert.assertEquals(2, resultHandler.getAnalysisResults().size());
    }

    @Test
    public void mustProducePositiveResult() {
        ArpPacket packet = generateReplyArpPacket(generateMacAddress(), generateInetAddress(),
                generateMacAddress(), generateInetAddress());
        getStorageInstance().put(new PacketInfo<>(packet));
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(new PacketInfo<>(
                generateReplyArpPacket(generateMacAddress(), generateInetAddress(), generateMacAddress(),
                        generateInetAddress())));
        Assert.assertEquals(0, resultHandler.getAnalysisResults().size());
    }
}
