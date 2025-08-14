package vmdragonslayer.api;

/**
 * System Statistics for Performance Monitoring
 */
public class SystemStats {
    public double averageResponseTime = 0.0;
    public double successRate = 0.0;
    public int activeTasks = 0;
    public boolean hasStandardEngines = false;
    
    public SystemStats() {}
    
    public SystemStats(double averageResponseTime, double successRate, int activeTasks, boolean hasStandardEngines) {
        this.averageResponseTime = averageResponseTime;
        this.successRate = successRate;
        this.activeTasks = activeTasks;
        this.hasStandardEngines = hasStandardEngines;
    }
}