package by.psu.arp.launcher;

import by.psu.arp.common.domain.launcher.ILauncher;
import by.psu.arp.common.util.logging.ArpLogger;
import by.psu.arp.executor.SenderExecutor;
import by.psu.arp.packet.sender.impl.PacketSenderFactory;
import org.apache.commons.lang3.math.NumberUtils;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.List;

/**
 * Sender launcher
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public class SenderLauncher implements ILauncher {

    private static final Logger LOGGER = ArpLogger.getLogger();
    private static final String FIND_ALL_DEVICES_ERROR = "Failed to get list of interfaces.";
    private static final String CREATE_SENDER_FOR_NIF_ERROR
            = "Unable to create packet sender for [{}] network interface.";
    private static final String ATTEMPT_TO_STOP_EXECUTOR = "Attempt to stop executor.";
    private static final String THREAD_GROUP = "sender-launcher";

    private List<SenderExecutor> executors;
    private ThreadGroup threadGroup;

    public SenderLauncher() {
        threadGroup = new ThreadGroup(THREAD_GROUP);
    }

    @Override
    public void launch() {
        List<PcapNetworkInterface> interfaces = null;
        try {
            interfaces = Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            LOGGER.error(FIND_ALL_DEVICES_ERROR, e);
            return;
        }
        executors = new ArrayList<>(interfaces.size());
        for (PcapNetworkInterface networkInterface : interfaces) {
            SenderExecutor senderExecutor;
            try {
                senderExecutor = new SenderExecutor(PacketSenderFactory.create(networkInterface), 1000);
            } catch (PcapNativeException e) {
                LOGGER.error(CREATE_SENDER_FOR_NIF_ERROR, networkInterface);
                continue;
            }
            new Thread(threadGroup, senderExecutor, THREAD_GROUP + "-" + networkInterface.getName()).start();
            executors.add(senderExecutor);
        }

    }

    @Override
    public void stop() {
        if (executors.size() > NumberUtils.INTEGER_ZERO) {
            LOGGER.info(ATTEMPT_TO_STOP_EXECUTOR);
            executors.forEach(SenderExecutor::stop);
        }
    }
}
