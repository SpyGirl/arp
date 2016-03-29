package by.psu.arp.common.domain.packet;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.pcap4j.packet.Packet;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * <p>
 * Date: Mar 24, 2016
 * </p>
 */
public class PacketInfo<T extends Packet> implements Serializable {

    private T packet;
    private LocalDateTime caught;

    public PacketInfo(T packet) {
        this.packet = packet;
        this.caught = LocalDateTime.now();
    }

    public PacketInfo(T packet, LocalDateTime caught) {
        this.packet = packet;
        this.caught = caught;
    }

    public T getPacket() {
        return packet;
    }

    public void setPacket(T packet) {
        this.packet = packet;
    }

    public LocalDateTime getCaught() {
        return caught;
    }

    public void setCaught(LocalDateTime caught) {
        this.caught = caught;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof PacketInfo<?>)) return false;

        PacketInfo<?> that = (PacketInfo<?>) o;

        return new EqualsBuilder()
                .append(this.packet, that.packet)
                .append(this.caught, that.caught)
                .isEquals();

    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder()
                .append(packet)
                .append(caught)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append(packet)
                .append(caught)
                .toString();
    }
}
