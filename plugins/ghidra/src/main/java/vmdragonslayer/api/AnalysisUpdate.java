package vmdragonslayer.api;

/**
 * Real-time Analysis Update from WebSocket
 */
public class AnalysisUpdate {
    private final String type;
    private final double progress;
    private final String status;
    private final String message;
    
    public AnalysisUpdate(String type, double progress, String status, String message) {
        this.type = type;
        this.progress = progress;
        this.status = status;
        this.message = message;
    }
    
    public String getType() { return type; }
    public double getProgress() { return progress; }
    public String getStatus() { return status; }
    public String getMessage() { return message; }
}