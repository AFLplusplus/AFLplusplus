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
// Find patch points for untracer tools (e.g. afl++ utils/afl_untracer)
//
//   Copy to ..../Ghidra/Features/Search/ghidra_scripts/
//   Writes the results to ~/Desktop/patches.txt
//
//   This is my very first Ghidra script. I am sure this could be done better.
//
//@category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;

import java.io.*;

public class ghidra_get_patchpoints extends GhidraScript {

	@Override
	public void run() throws Exception {

		long segment_start = 0;
		Memory memory = currentProgram.getMemory();
		MultEntSubModel model = new MultEntSubModel(currentProgram);
		CodeBlockIterator subIter = model.getCodeBlocks(monitor);
		BufferedWriter out = new BufferedWriter(new FileWriter(System.getProperty("user.home") + File.separator + "Desktop" + File.separator + "patches.txt"));

		while (subIter.hasNext()) {

			CodeBlock multiEntryBlock = subIter.next();
			SimpleBlockModel basicBlockModel = new SimpleBlockModel(currentProgram);
			CodeBlockIterator bbIter = basicBlockModel.getCodeBlocksContaining(multiEntryBlock, monitor);

			while (bbIter.hasNext()) {

				CodeBlock basicBlock = bbIter.next();

				if (segment_start == 0) {

					Address firstAddr = basicBlock.getFirstStartAddress();
					long firstBlockAddr = firstAddr.getAddressableWordOffset();
					MemoryBlock mb = memory.getBlock(firstAddr);
					Address startAddr = mb.getStart();
					Address endAddr = mb.getEnd();
					segment_start = startAddr.getAddressableWordOffset();
					if ((firstBlockAddr - segment_start) >= 0x1000)
					  segment_start += 0x1000;
					long segment_end = endAddr.getAddressableWordOffset();
					long segment_size = segment_end - segment_start;
					if ((segment_size % 0x1000) > 0)
					  segment_size = (((segment_size / 0x1000) + 1) * 0x1000);
					out.write(currentProgram.getName() + ":0x" + Long.toHexString(segment_size) + "\n"); 
					//println("Start: " + Long.toHexString(segment_start));
					//println("End: " + Long.toHexString(segment_end));

				}
 	   		        
 	   		        if (basicBlock.getFirstStartAddress().getAddressableWordOffset() - segment_start > 0)
 	   		        	out.write("0x" + Long.toHexString(basicBlock.getFirstStartAddress().getAddressableWordOffset() - segment_start) + "\n");

			}
		}

		out.close();

	}
}
