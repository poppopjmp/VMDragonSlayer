/*
 * VMDragonSlayer - Advanced VM detection and analysis library
 * Copyright (C) 2025 van1sh
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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