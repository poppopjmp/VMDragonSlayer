package vmdragonslayer.api;

/**
 * System Statistics and Performance Metrics
 */
public class SystemStatistics {
    private final int activeTasks;
    private final int totalDecisions;
    private final double systemUptime;
    private final boolean hasStandardEngines;
    
    public SystemStatistics(int activeTasks, int totalDecisions, double systemUptime, boolean hasStandardEngines) {
        this.activeTasks = activeTasks;
        this.totalDecisions = totalDecisions;
        this.systemUptime = systemUptime;
        this.hasStandardEngines = hasStandardEngines;
    }
    
    public int getActiveTasks() { return activeTasks; }
    public int getTotalDecisions() { return totalDecisions; }
    public double getSystemUptime() { return systemUptime; }
    public boolean hasStandardEngines() { return hasStandardEngines; }
    public boolean hasEngines() { return hasStandardEngines; }
}