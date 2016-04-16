package by.psu.arp.model.packet;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.pcap4j.packet.ArpPacket;

import java.io.Serializable;
import java.util.Date;

/**
 * <p>
 * Date: Mar 24, 2016
 * </p>
 */
public class PacketInfo<T extends ArpPacket> implements Serializable {

    private T packet;
    private Date dateTime;

    public PacketInfo(T packet) {
        this.packet = packet;
        this.dateTime = new Date(System.nanoTime());
    }

    public T getPacket() {
        return packet;
    }

    public void setPacket(T packet) {
        this.packet = packet;
    }

    public Date getDateTime() {
        return dateTime;
    }

    public void setDateTime(Date dateTime) {
        this.dateTime = dateTime;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof PacketInfo<?>)) return false;

        PacketInfo<?> that = (PacketInfo<?>) o;

        return new EqualsBuilder()
                .append(this.packet, that.packet)
                .append(this.dateTime, that.dateTime)
                .isEquals();

    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder()
                .append(packet)
                .append(dateTime)
                .toHashCode();
    }

    @Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append(packet)
                .append(dateTime)
                .toString();
    }
}
