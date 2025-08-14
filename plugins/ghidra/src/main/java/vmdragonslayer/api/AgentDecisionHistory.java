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

import java.util.List;
import java.util.ArrayList;

/**
 * Agent Decision History for AI Dashboard
 */
public class AgentDecisionHistory {
    public List<AIDecision> decisions;
    public AgentStatistics statistics;
    
    public AgentDecisionHistory() {
        this.decisions = new ArrayList<>();
        this.statistics = new AgentStatistics();
    }
    
    public static class AgentStatistics {
        public int totalDecisions = 0;
        public double averageConfidence = 0.0;
        public String learningStatus = "Initializing";
        
        public AgentStatistics() {}
    }
}