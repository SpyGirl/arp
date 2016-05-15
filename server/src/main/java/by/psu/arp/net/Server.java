package by.psu.arp.net;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.util.logging.ArpLogger;
import org.slf4j.Logger;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Date: Май 14, 2016
 */
public class Server {

    private static final Logger LOGGER = ArpLogger.getLogger();

    private int maxConnectionsCount;
    private ServerSocket server;
    private List<Socket> clients = new ArrayList<>();

    private ExecutorService serverExecutor;

    public Server(int port, int maxConnectionsCount) {
        serverExecutor = Executors.newFixedThreadPool(maxConnectionsCount + 1);
        try {
            server = new ServerSocket(port);
        } catch (IOException e) {
            LOGGER.error("Cannot listen on port {}.", port);
        }
    }

    @SuppressWarnings("unchecked")
    public void start() {
        serverExecutor.execute(() -> {
            while (!server.isClosed()) {
                try {
                    Socket client = server.accept();
                    serverExecutor.execute(() -> {
                        try {
                            ObjectInputStream stream = new ObjectInputStream(client.getInputStream());
                            Collection<AnalysisErrorResultHandler> results =
                                    (Collection<AnalysisErrorResultHandler>) stream.readObject();
                            LOGGER.info("Attention! Some things seem suspicious:\n{}", results);
                            stream.close();
                        } catch (IOException e) {
                            LOGGER.error("Error while opening input stream.", e);
                        } catch (ClassNotFoundException e) {
                            LOGGER.error("Error while reading an object from input stream.", e);
                        }
                    });
                } catch (IOException e) {
                    LOGGER.error("Error while accepting a client connection.", e);
                }
            }
        });
    }

    public void shutdown() {
        LOGGER.info("Shutdown the server.");
        clients.forEach((socket) -> {
            try {
                socket.close();
            } catch (IOException e) {
                LOGGER.error("I/O exception while closing the socket {}.", socket);
            }
        });
        try {
            server.close();
        } catch (IOException e) {
            LOGGER.error("I/O exception while closing the server {}.", server);
        }
        serverExecutor.shutdown();
    }
}
