package by.psu.arp.launcher.impl;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.executor.api.IAnalyzerExecutor;
import by.psu.arp.executor.impl.AnalyzerExecutor;
import by.psu.arp.launcher.api.IAnalyzerLauncher;

import java.util.Collection;

/**
 * Analyzer executor launcher.
 * <p>
 * Created: 09/05/16
 * </p>
 */
public class AnalyzerLauncher implements IAnalyzerLauncher {

    private static final String THREAD_GROUP = "analyzer-launcher";

    private ThreadGroup threadGroup;
    private IAnalyzerExecutor executor;

    public AnalyzerLauncher() {
        threadGroup = new ThreadGroup(THREAD_GROUP);
        executor = new AnalyzerExecutor();
    }

    @Override
    public Collection<AnalysisErrorResultHandler> getResults() {
        return executor.getResults();
    }

    @Override
    public void launch() {
        new Thread(threadGroup, executor, THREAD_GROUP).start();
    }

    @Override
    public void stop() {
        executor.stop();
    }
}
