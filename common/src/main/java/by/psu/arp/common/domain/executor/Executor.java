package by.psu.arp.common.domain.executor;

/**
 * Executor interface
 * <p>
 * Date: Mar 27, 2016
 * </p>
 */
public interface Executor extends Runnable {

    /**
     * Stops execution.
     */
    void stop();
}
