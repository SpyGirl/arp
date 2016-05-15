package by.psu.arp.executor.api;

import by.psu.arp.analysis.AnalysisErrorResultHandler;
import by.psu.arp.executor.IExecutor;

import java.util.Collection;

/**
 * Date: Май 10, 2016
 */
public interface IAnalyzerExecutor extends IExecutor {

    Collection<AnalysisErrorResultHandler> getResults();
}
