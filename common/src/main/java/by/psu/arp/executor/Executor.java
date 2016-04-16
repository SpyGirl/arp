package by.psu.arp.executor;

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
