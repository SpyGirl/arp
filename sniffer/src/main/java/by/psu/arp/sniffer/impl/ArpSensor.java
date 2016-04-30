package by.psu.arp.sniffer.impl;

import by.psu.arp.listener.impl.ArpPacketListener;
import by.psu.arp.sniffer.api.AbstractSensor;
import org.pcap4j.core.PcapHandle;

/**
 * Arp sensor.
 * <p>
 * Date: Mar 20, 2016
 * </p>
 */
public class ArpSensor extends AbstractSensor {

    /**
     * Constructor. Passes arp packet listener to abstract sensor.
     *
     * @param handle
     */
    protected ArpSensor(PcapHandle handle) {
        super(handle, new ArpPacketListener());
    }
}
