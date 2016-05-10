package by.psu.arp.launcher;

import by.psu.arp.executor.AnalyzerExecutor;
import by.psu.arp.launcher.api.AbstractLauncher;

import java.util.ArrayList;

/**
 * Analyzer executor launcher.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public class AnalyzerLauncher extends AbstractLauncher {

    private static final String THREAD_GROUP = "analyzer-launcher";

    public AnalyzerLauncher() {
        threadGroup = new ThreadGroup(THREAD_GROUP);
        executors = new ArrayList<>(1);
    }

    @Override
    public void launch() {
        AnalyzerExecutor executor = new AnalyzerExecutor();
        new Thread(threadGroup, executor).start();
        executors.add(executor);
    }
}
