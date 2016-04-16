package by.psu.arp.model.analysis;

import java.util.ArrayList;
import java.util.List;

/**
 * Analysis error result handler.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class AnalysisErrorResultHandler {

    private List<AnalysisResult> analysisResults = new ArrayList<AnalysisResult>();

    /**
     * Adds error.
     *
     * @param analysisResult analysis result
     */
    public void addError(AnalysisResult analysisResult) {
        analysisResults.add(analysisResult);
    }

    public boolean hasErrors() {
        return analysisResults.size() > 0;
    }

    public List<AnalysisResult> getAnalysisResults() {
        return analysisResults;
    }
}
