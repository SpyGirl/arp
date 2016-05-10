package by.psu.arp.packet.comparator;

import by.psu.arp.packet.PacketInfo;
import org.pcap4j.packet.Packet;

import java.util.Comparator;

/**
 * DateTime comparator for PacketInfo..
 * <p>
 * Date: Apr 05, 2016
 * </p>
 */
public final class DateTimePacketInfoComparator<T extends PacketInfo<? extends Packet>> implements Comparator<T> {

    @Override
    public int compare(T left, T right) {
        return right.getDateTime().compareTo(left.getDateTime());
    }
}
