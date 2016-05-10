package by.psu.arp.analyzer.plain;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.packet.PacketInfo;
import org.junit.Assert;
import org.junit.Test;
import org.pcap4j.packet.ArpPacket;

import java.net.InetAddress;

import static by.psu.arp.analyzer.plain.util.PacketUtils.*;
import static by.psu.arp.storage.PacketInfoStorage.getStorageInstance;

/**
 * Tests for {@link IpToMacMappingAnalyzer}.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public class IpToMacMappingAnalyzerTest {

    private IpToMacMappingAnalyzer analyzer = new IpToMacMappingAnalyzer();

    @Test
    public void mustProduceMultipleMacForIpResult() {
        InetAddress srcInetAddr = generateInetAddress();
        ArpPacket packet = generateReplyArpPacket(generateMacAddress(), srcInetAddr,
                generateMacAddress(), generateInetAddress());
        getStorageInstance().put(new PacketInfo<>(packet));
        AnalysisErrorResultHandler resultHandler = analyzer.analyze(new PacketInfo<>(generateReplyArpPacket(
                generateMacAddress(), srcInetAddr, generateMacAddress(), generateInetAddress())));
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
