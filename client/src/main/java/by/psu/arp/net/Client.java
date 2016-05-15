package by.psu.arp.net;

import by.psu.arp.util.logging.ArpLogger;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;

/**
 * Date: Май 14, 2016
 */
public class Client {

    private static final Logger LOGGER = ArpLogger.getLogger();

    private Socket socket;
    private String host;
    private int port;

    public Client(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void send(Object data) throws IOException {
        init();
        try {
            ObjectOutputStream stream = new ObjectOutputStream(socket.getOutputStream());
            stream.writeObject(data);
            stream.close();
            socket.close();
        } catch (IOException e) {
            LOGGER.error("I/O error while opening output stream", e);
            throw e;
        }
    }

    private void init() throws IOException {
        try {
            socket = new Socket(host, port);
        } catch (IOException e) {
            LOGGER.error("Unable to connect to the server.", e);
            throw e;
        }
    }
}
