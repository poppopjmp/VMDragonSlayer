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