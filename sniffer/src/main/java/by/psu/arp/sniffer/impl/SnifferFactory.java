package by.psu.arp.sniffer.impl;

import by.psu.arp.sniffer.api.ISniffer;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import static org.pcap4j.core.BpfProgram.BpfCompileMode.OPTIMIZE;
import static org.pcap4j.core.PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

/**
 * Sensor factory.
 * Date: Mar 23, 2016
 */
public abstract class SnifferFactory {

    private static final int SNAPSHOT_LENGTH = 65536;
    private static final int READ_TIMEOUT = 20;

    /**
     * Constructor.
     */
    private SnifferFactory() {
        throw new UnsupportedOperationException("This object must never be created.");
    }

    /**
     * Creates a sensor.
     *
     * @param networkInterface pcap network interface
     * @return created sensor
     * @throws PcapNativeException
     * @throws NotOpenException
     */
    public static ISniffer create(PcapNetworkInterface networkInterface)
            throws PcapNativeException, NotOpenException {
        PcapHandle handle = networkInterface.openLive(SNAPSHOT_LENGTH, PROMISCUOUS, READ_TIMEOUT);
        handle.setFilter("arp", OPTIMIZE);
        return new ArpSniffer(handle);
    }
}
