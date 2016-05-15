package by.psu.arp.settings;

import by.psu.arp.util.logging.ArpLogger;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Date: Май 15, 2016
 */
public class SettingsHolder {

    private static final Logger LOGGER = ArpLogger.getLogger();

    private static Properties properties = new Properties();
    private static boolean isLoaded = false;

    private SettingsHolder () {
        throw new UnsupportedOperationException("This object must never be instantiated.");
    }

    /**
     * Loads settings from properties.
     * @param path full file name.
     */
    public static void loadSettings(String path) {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try (InputStream stream = loader.getResourceAsStream(path)) {
            properties.load(stream);
            isLoaded = true;
        } catch (IOException e) {
            LOGGER.error("I/O error while loading project properties.", e);
        }
    }

    public static String getProperty(String key) {
        if (!isLoaded) {
            throw new RuntimeException("Properties are not loaded. Use 'loadSettings' first.");
        }
        return properties.getProperty(key);
    }
}
