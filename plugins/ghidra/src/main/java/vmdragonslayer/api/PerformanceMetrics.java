package vmdragonslayer.api;

/**
 * Performance Metrics from Enterprise Engines
 */
public class PerformanceMetrics {
    private final int memoryPeakMB;
    private final double cpuTime;
    private final double throughputMbps;
    
    public PerformanceMetrics(int memoryPeakMB, double cpuTime, double throughputMbps) {
        this.memoryPeakMB = memoryPeakMB;
        this.cpuTime = cpuTime;
        this.throughputMbps = throughputMbps;
    }
    
    public int getMemoryPeakMB() { return memoryPeakMB; }
    public double getCpuTime() { return cpuTime; }
    public double getThroughputMbps() { return throughputMbps; }
}