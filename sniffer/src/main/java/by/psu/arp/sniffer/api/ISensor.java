package by.psu.arp.sniffer.api;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.packet.ArpPacket;

/**
 * Sensor interface.
 * <p>
 * Date: Mar 20, 2016
 * </p>
 */
public interface ISensor {

    /**
     * Catches next packet and returns it. Waits until catch a packet.
     *
     * @return caught packet
     * @throws PcapNativeException
     * @throws InterruptedException
     * @throws NotOpenException
     */
    ArpPacket catchNextPacket() throws PcapNativeException, InterruptedException, NotOpenException;

    /**
     * Stops catching packets.
     *
     * @throws NotOpenException
     */
    void stop() throws NotOpenException;
}
