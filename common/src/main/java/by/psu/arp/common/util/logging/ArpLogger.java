package by.psu.arp.common.util.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides common logger for all interested classes.
 * Date: Mar 20, 2016
 */
public final class ArpLogger {

    private ArpLogger() {
        throw new UnsupportedOperationException("This object must never be created.");
    }

    public static Logger getLogger() {
        final Throwable t = new Throwable();
        t.fillInStackTrace();
        final String clazz = t.getStackTrace()[1].getClassName();
        return LoggerFactory.getLogger(clazz);
    }
}
