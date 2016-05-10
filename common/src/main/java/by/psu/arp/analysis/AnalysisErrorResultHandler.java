package by.psu.arp.analysis;

import java.util.ArrayList;
import java.util.List;

/**
 * Analysis error result handler.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class AnalysisErrorResultHandler implements Comparable<AnalysisErrorResultHandler> {

    private List<AnalysisResult> analysisResults = new ArrayList<>();

    /**
     * Adds error.
     *
     * @param analysisResult analysis result
     */
    public void addError(AnalysisResult analysisResult) {
        analysisResults.add(analysisResult);
    }

    public void addErrors(List<AnalysisResult> analysisResults) {
        this.analysisResults.addAll(analysisResults);
    }

    public boolean hasErrors() {
        return analysisResults.size() > 0;
    }

    public List<AnalysisResult> getAnalysisResults() {
        return analysisResults;
    }

    @Override
    public int compareTo(AnalysisErrorResultHandler that) {
        return analysisResults.size() - that.analysisResults.size();
    }
}
