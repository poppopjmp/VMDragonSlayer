package vmdragonslayer.api;

import java.util.List;

/**
 * Engine Status Information
 */
public class EngineStatus {
    private final boolean available;
    private final List<String> availableEngines;
    
    public EngineStatus(boolean available, List<String> availableEngines) {
        this.available = available;
        this.availableEngines = availableEngines;
    }
    
    public boolean isAvailable() { return available; }
    public List<String> getAvailableEngines() { return availableEngines; }
}