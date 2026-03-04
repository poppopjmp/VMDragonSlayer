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