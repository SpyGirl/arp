package by.psu.arp.sniffer.impl;

import by.psu.arp.listener.impl.ArpPacketSniffer;
import by.psu.arp.sniffer.api.AbstractSniffer;
import org.pcap4j.core.PcapHandle;

/**
 * Arp sensor.
 * <p>
 * Date: Mar 20, 2016
 * </p>
 */
public class ArpSniffer extends AbstractSniffer {

    /**
     * Constructor. Passes arp packet listener to abstract sensor.
     *
     * @param handle
     */
    protected ArpSniffer(PcapHandle handle) {
        super(handle, new ArpPacketSniffer());
    }
}
