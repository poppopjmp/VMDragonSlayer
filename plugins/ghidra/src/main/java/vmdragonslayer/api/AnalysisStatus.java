package vmdragonslayer.api;

/**
 * Analysis Status for Progress Monitoring
 */
public class AnalysisStatus {
    public String status = "unknown";
    public double progress = 0.0;
    public String error = null;
    public String message = "";
    
    public AnalysisStatus() {}
    
    public AnalysisStatus(String status, double progress) {
        this.status = status;
        this.progress = progress;
    }
}