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

/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package vmdragonslayer;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class VMDragonSlayerAnalyzer extends AbstractAnalyzer {

	public VMDragonSlayerAnalyzer() {

		// Name the analyzer and give it a description.

		super("My Analyzer", "Analyzer description goes here", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.

		return false;
	}
}
