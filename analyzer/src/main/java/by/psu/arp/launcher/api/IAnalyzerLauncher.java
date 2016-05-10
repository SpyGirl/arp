package by.psu.arp.launcher.api;

import by.psu.arp.analysis.AnalysisErrorResultHandler;

/**
 * Date: Май 10, 2016
 */
public interface IAnalyzerLauncher extends ILauncher {

    AnalysisErrorResultHandler getResult();
}
