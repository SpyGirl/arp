package by.psu.arp.launcher.api;

import by.psu.arp.analysis.AnalysisErrorResultHandler;

import java.util.Collection;

/**
 * Date: Май 10, 2016
 */
public interface IAnalyzerLauncher extends ILauncher {

    Collection<AnalysisErrorResultHandler> getResults();
}
