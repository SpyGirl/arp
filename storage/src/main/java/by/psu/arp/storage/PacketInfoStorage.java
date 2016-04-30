package by.psu.arp.storage;

import by.psu.arp.packet.PacketInfo;
import by.psu.arp.packet.comparator.DateTimePacketInfoComparator;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.util.MacAddress;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListSet;

import static by.psu.arp.util.packet.PacketInfoUtils.*;
import static org.pcap4j.packet.namednumber.ArpOperation.REQUEST;

/**
 * Packet information storage.
 * Implements Singleton design pattern. Uses concurrent collections.
 * So all operations are thread safe.
 * <p>
 * Date: Mar 24, 2016
 * </p>
 */
public final class PacketInfoStorage<T extends PacketInfo<ArpPacket>> implements Serializable {

    private static final DateTimePacketInfoComparator<PacketInfo<ArpPacket>>
            DATE_TIME_PACKET_INFO_COMPARATOR = new DateTimePacketInfoComparator<>();
    private static final PacketInfoStorage INSTANCE = new PacketInfoStorage();

    private ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> ipRequests;
    private ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> ipReplays;

    private ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> macRequests;
    private ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> macReplays;


    private PacketInfoStorage() {
        ipRequests = new ConcurrentHashMap<>();
        ipReplays = new ConcurrentHashMap<>();
        macRequests = new ConcurrentHashMap<>();
        macReplays = new ConcurrentHashMap<>();
    }

    /**
     * Gets storage instance.
     *
     * @return storage instance
     */
    public static PacketInfoStorage<PacketInfo<ArpPacket>> getStorageInstance() {
        return INSTANCE;
    }

    /**
     * Adds packet info to ipRequests or ipReplays collection.
     *
     * @param packetInfo packet info to add
     */
    public void put(T packetInfo) {
        boolean request = REQUEST.equals(getArpOperation(packetInfo));
        ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> ipMap = request ? ipRequests : ipReplays;
        storeByIp(packetInfo, ipMap);
        ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> macMap = request ? macRequests : macReplays;
        storeByMac(packetInfo, macMap);
    }

    /**
     * Gets set of request packet info-s.
     *
     * @param inetAddress source IP address
     * @return packet info set
     */
    public ConcurrentSkipListSet<T> getRequests(InetAddress inetAddress) {
        return ipRequests.get(inetAddress);
    }

    /**
     * Gets set of replay packet info-s.
     *
     * @param macAddress source mac address
     * @return packet info set
     */
    public ConcurrentSkipListSet<T> getReplays(MacAddress macAddress) {
        return macReplays.get(macAddress);
    }

    /**
     * Gets set of request packet info-s.
     *
     * @param macAddress source IP address
     * @return packet info set
     */
    public ConcurrentSkipListSet<T> getRequests(MacAddress macAddress) {
        return macRequests.get(macAddress);
    }

    /**
     * Gets set of replay packet info-s.
     *
     * @param inetAddress source IP address
     * @return packet info set
     */
    public ConcurrentSkipListSet<T> getReplays(InetAddress inetAddress) {
        return ipReplays.get(inetAddress);
    }

    /**
     * Removes ipRequests by inet address.
     *
     * @param inetAddress inet address
     * @return removed value
     */
    public ConcurrentSkipListSet<T> removeRequsts(InetAddress inetAddress) {
        return ipRequests.remove(inetAddress);
    }

    /**
     * Removes ipReplays by inet address.
     *
     * @param inetAddress inet address
     * @return removed value
     */
    public ConcurrentSkipListSet<T> removeReplays(InetAddress inetAddress) {
        return ipReplays.remove(inetAddress);
    }

    /**
     * Removes ipRequests by mac address.
     *
     * @param macAddress mac address
     * @return removed value
     */
    public ConcurrentSkipListSet<T> removeRequsts(MacAddress macAddress) {
        return macRequests.remove(macAddress);
    }

    /**
     * Removes ipReplays by mac address.
     *
     * @param macAddress mac address
     * @return removed value
     */
    public ConcurrentSkipListSet<T> removeReplays(MacAddress macAddress) {
        return macReplays.remove(macAddress);
    }

    public void cleanUptoTime(Date dateTime) {
        cleanUptoDateTime(ipReplays.values(), dateTime);
        cleanUptoDateTime(ipRequests.values(), dateTime);
        cleanUptoDateTime(macReplays.values(), dateTime);
        cleanUptoDateTime(macRequests.values(), dateTime);
    }

    private void cleanUptoDateTime(Collection<ConcurrentSkipListSet<T>> values, Date dateTime) {
        for (ConcurrentSkipListSet<T> value : values) {
            Iterator<T> iterator = value.iterator();
            while (iterator.hasNext()) {
                T packet = iterator.next();
                if (packet.getDateTime().before(dateTime)) {
                    iterator.remove();
                }
            }
        }
    }

    private void storeByIp(T packetInfo, ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> map) {
        InetAddress srcAddress = getSourceInetAddress(packetInfo);
        ConcurrentSkipListSet<T> skipListSet = map.get(srcAddress);
        if (skipListSet == null) {
            skipListSet = createEmptyConcurrentSkipListSet();
        }
        boolean addResult = skipListSet.add(packetInfo);
        if (addResult) {
            map.put(srcAddress, skipListSet);
        }
    }

    private void storeByMac(T packetInfo, ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> map) {
        MacAddress macAddress = getSourceMacAddress(packetInfo);
        ConcurrentSkipListSet<T> skipListSet = map.get(macAddress);
        if (skipListSet == null) {
            skipListSet = createEmptyConcurrentSkipListSet();
        }
        boolean addResult = skipListSet.add(packetInfo);
        if (addResult) {
            map.put(macAddress, skipListSet);
        }
    }

    private ConcurrentSkipListSet<T> createEmptyConcurrentSkipListSet() {
        return new ConcurrentSkipListSet<>(DATE_TIME_PACKET_INFO_COMPARATOR);
    }
}
