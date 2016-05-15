package by.psu.arp.analysis;

import org.apache.commons.lang3.builder.ToStringBuilder;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import static org.apache.commons.lang3.builder.ToStringStyle.SHORT_PREFIX_STYLE;

/**
 * Analysis error result handler.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public class AnalysisErrorResultHandler implements Comparable<AnalysisErrorResultHandler>, Serializable {

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

    @Override
    public String toString() {
        return new ToStringBuilder(this, SHORT_PREFIX_STYLE)
                .append("analysisResults", analysisResults)
                .toString();
    }
}
