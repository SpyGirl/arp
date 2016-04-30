package by.psu.arp.launcher;

import by.psu.arp.executor.SensorExecutor;
import by.psu.arp.sniffer.impl.SensorFactory;
import by.psu.arp.util.logging.ArpLogger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Sensor launcher
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class SensorLauncher extends AbstractLauncher {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final String FIND_ALL_DEVICES_ERROR = "Failed to get list of interfaces.";
    private static final String CREATE_SENSOR_FOR_NIF_ERROR
            = "Unable to create packet sensor for [{}] network interface.";
    private static final String ATTEMPT_TO_STOP_EXECUTOR = "Attempt to stop executor.";
    private static final String THREAD_GROUP = "sensor-launcher";

    public SensorLauncher() {
        threadGroup = new ThreadGroup(THREAD_GROUP);
    }

    @Override
    public void launch() {
        List<PcapNetworkInterface> interfaces;
        try {
            interfaces = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            LOGGER.error(FIND_ALL_DEVICES_ERROR, e);
            return;
        }
        executors = new ArrayList<>(interfaces.size());
        for (PcapNetworkInterface networkInterface : interfaces) {
            SensorExecutor sensorExecutor;
            try {
                sensorExecutor = new SensorExecutor(SensorFactory.create(networkInterface));
            } catch (PcapNativeException | NotOpenException e) {
                LOGGER.error(CREATE_SENSOR_FOR_NIF_ERROR, networkInterface);
                continue;
            }
            new Thread(threadGroup, sensorExecutor, THREAD_GROUP + "-" + networkInterface.getName())
                    .start();
            executors.add(sensorExecutor);
        }

    }
}
