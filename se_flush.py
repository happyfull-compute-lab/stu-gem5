import sys
from gem5.components.boards.simple_board import SimpleBoard
from gem5.components.cachehierarchies.classic.private_l1_shared_l2_cache_hierarchy import PrivateL1SharedL2CacheHierarchy
from gem5.components.memory.single_channel import SingleChannelDDR3_1600
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.isas import ISA
from gem5.resources.resource import BinaryResource
from gem5.simulate.simulator import Simulator

processor = SimpleProcessor(cpu_type=CPUTypes.O3, isa=ISA.X86, num_cores=1)
board = SimpleBoard(
    clk_freq="3GHz", processor=processor,
    memory=SingleChannelDDR3_1600(size="2GiB"),
    cache_hierarchy=PrivateL1SharedL2CacheHierarchy(
        l1d_size="64KiB", l1i_size="64KiB", l2_size="8MiB"),
)
board.set_se_binary_workload(BinaryResource(local_path="flush_test"))
Simulator(board=board).run()
