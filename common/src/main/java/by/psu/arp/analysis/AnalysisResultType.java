package by.psu.arp.analysis;

/**
 * Analysis result type.
 * <p>
 * Date: Apr 07, 2016
 * </p>
 */
public enum AnalysisResultType {

    SUCCESS(true),
    REPLAY_WITHOUT_REQUEST(false),
    REPLAY_TIMEOUT_EXPIRE(false),
    MULTIPLE_MAC_FOR_IP(false),
    MULTIPLE_IP_FOR_MAC(false),
    SPAM_FROM_MAC(false);

    private boolean result;

    AnalysisResultType(boolean result) {
        this.result = result;
    }

    public boolean getResult() {
        return result;
    }
}
