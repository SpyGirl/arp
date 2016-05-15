package by.psu.arp.storage;

import by.psu.arp.packet.PacketInfo;
import by.psu.arp.packet.comparator.DateTimePacketInfoComparator;
import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.util.MacAddress;
import org.slf4j.Logger;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.*;
import java.util.concurrent.*;

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

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final DateTimePacketInfoComparator<PacketInfo<ArpPacket>>
            DATE_TIME_PACKET_INFO_COMPARATOR = new DateTimePacketInfoComparator<>();
    private static final PacketInfoStorage INSTANCE = new PacketInfoStorage();
    private static final int COLLECTIONS_COUNT = 4;

    private ConcurrentSkipListSet<T> packetsToAnalyze;

    private ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> ipRequests;
    private ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> ipReplays;

    private ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> macRequests;
    private ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> macReplays;

    private ExecutorService executorService;

    private PacketInfoStorage() {
        packetsToAnalyze = new ConcurrentSkipListSet<>(DATE_TIME_PACKET_INFO_COMPARATOR);
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
        packetsToAnalyze.add(packetInfo);
        boolean isRequest = REQUEST.equals(getArpOperation(packetInfo));
        ConcurrentHashMap<InetAddress, ConcurrentSkipListSet<T>> ipMap = isRequest ? ipRequests : ipReplays;
        storeByIp(packetInfo, ipMap);
        ConcurrentHashMap<MacAddress, ConcurrentSkipListSet<T>> macMap = isRequest ? macRequests : macReplays;
        storeByMac(packetInfo, macMap);
    }

    /**
     * Retrieves and removes first element from set.
     *
     * @return packet info.
     */
    public T pollPacket() {
        return packetsToAnalyze.pollFirst();
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
    public ConcurrentSkipListSet<T> removeRequests(InetAddress inetAddress) {
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
    public ConcurrentSkipListSet<T> removeRequests(MacAddress macAddress) {
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

    public int cleanUpToDateTime(Date dateTime) {
        List<FutureTask<Integer>> tasks = runCleanUpTasks(dateTime);
        int cleanedItems = 0;
        while (tasks.size() > 0) {
            Iterator<FutureTask<Integer>> taskIterator = tasks.iterator();
            while (taskIterator.hasNext()) {
                FutureTask<Integer> futureTask = taskIterator.next();
                if (futureTask.isDone()) {
                    try {
                        cleanedItems += futureTask.get();
                    } catch (InterruptedException | ExecutionException e) {
                        LOGGER.error("Error while getting result of analyzer.", e);
                    }
                    taskIterator.remove();
                }
            }
        }
        executorService.shutdown();
        return cleanedItems;
    }

    private List<FutureTask<Integer>> runCleanUpTasks(Date dateTime) {
        executorService = Executors.newFixedThreadPool(COLLECTIONS_COUNT);
        List<FutureTask<Integer>> tasks = new ArrayList<>(COLLECTIONS_COUNT);
        FutureTask<Integer> task = new FutureTask<>(new CallableStorageCleaner<>(ipReplays.values(), dateTime));
        tasks.add(task);
        executorService.execute(task);
        task = new FutureTask<>(new CallableStorageCleaner<>(ipRequests.values(), dateTime));
        tasks.add(task);
        executorService.execute(task);
        task = new FutureTask<>(new CallableStorageCleaner<>(macReplays.values(), dateTime));
        tasks.add(task);
        executorService.execute(task);
        task = new FutureTask<>(new CallableStorageCleaner<>(macRequests.values(), dateTime));
        tasks.add(task);
        executorService.execute(task);
        return tasks;
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

    private static class CallableStorageCleaner<T extends PacketInfo<ArpPacket>> implements Callable<Integer> {

        private Collection<ConcurrentSkipListSet<T>> values;
        private Date dateTime;

        public CallableStorageCleaner(Collection<ConcurrentSkipListSet<T>> values, Date dateTime) {
            this.values = values;
            this.dateTime = dateTime;
        }

        @Override
        public Integer call() throws Exception {
            int count = 0;
            for (ConcurrentSkipListSet<T> value : values) {
                Iterator<T> iterator = value.iterator();
                while (iterator.hasNext()) {
                    PacketInfo<?> packet = iterator.next();
                    if (packet.getDateTime().before(dateTime)) {
                        iterator.remove();
                        count++;
                    }
                }
            }
            return count;
        }
    }
}
