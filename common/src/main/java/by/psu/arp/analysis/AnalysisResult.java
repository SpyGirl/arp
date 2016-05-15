package by.psu.arp.analysis;

import by.psu.arp.packet.PacketInfo;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.pcap4j.packet.ArpPacket;

import java.io.Serializable;

import static org.apache.commons.lang3.builder.ToStringStyle.SHORT_PREFIX_STYLE;

/**
 * Analysis result.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class AnalysisResult implements Serializable {

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AnalysisResult that = (AnalysisResult) o;
        return new EqualsBuilder()
                .append(packetInfo, that.packetInfo)
                .append(resultType, that.resultType)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder()
                .append(packetInfo)
                .append(resultType)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, SHORT_PREFIX_STYLE)
                .append("packetInfo", packetInfo)
                .append("resultType", resultType)
                .toString();
    }
}
