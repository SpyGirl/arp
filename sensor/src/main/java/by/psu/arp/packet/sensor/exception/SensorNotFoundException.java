package by.psu.arp.packet.sensor.exception;

/**
 * Sensor not found exception.
 * <p>
 * Date: Mar 23, 2016
 * </p>
 */
public class SensorNotFoundException extends RuntimeException {

    /**
     * Constructor.
     *
     * @param message error message
     */
    public SensorNotFoundException(String message) {
        super(message);
    }
}
