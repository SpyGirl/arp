package by.psu.arp.common.storage.impl;

import by.psu.arp.common.domain.packet.PacketInfo;
import by.psu.arp.common.storage.api.IStorage;
import org.pcap4j.packet.Packet;

import java.io.Serializable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

/**
 * Packet information storage.
 * Implements Singleton design pattern. Uses concurrent Blocking Queue. So all operations
 * are thread safe.
 * <p>
 * Date: Mar 24, 2016
 * </p>
 */
public final class PacketInfoStorage implements IStorage<PacketInfo<? extends Packet>>, Serializable {

    private static final PacketInfoStorage INSTANCE = new PacketInfoStorage();

    private BlockingQueue<PacketInfo<? extends Packet>> packets;

    private PacketInfoStorage() {
        packets = new ArrayBlockingQueue<>(1000);
    }

    public static PacketInfoStorage getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean put(PacketInfo<? extends Packet> packet) {
        return packets.offer(packet);
    }

    @Override
    public PacketInfo<? extends Packet> poll() {
        return packets.remove();
    }
}
