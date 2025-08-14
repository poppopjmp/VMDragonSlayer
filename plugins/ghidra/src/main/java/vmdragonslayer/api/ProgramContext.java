package vmdragonslayer.api;

/**
 * Program Context for AI Agent
 */
public class ProgramContext {
    private final String name;
    private final String path;
    private final String format;
    private final String language;
    private final int addressSize;
    
    public ProgramContext(String name, String path, String format, String language, int addressSize) {
        this.name = name;
        this.path = path;
        this.format = format;
        this.language = language;
        this.addressSize = addressSize;
    }
    
    // Getters
    public String getName() { return name; }
    public String getPath() { return path; }
    public String getFormat() { return format; }
    public String getLanguage() { return language; }
    public int getAddressSize() { return addressSize; }
}