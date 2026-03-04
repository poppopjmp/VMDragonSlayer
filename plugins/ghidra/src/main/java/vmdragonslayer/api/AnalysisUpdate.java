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