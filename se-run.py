import argparse
import m5
from m5.objects import SecurityTelemetryUnit

from m5.objects import (
    BiModeBP,
    LocalBP,
    LTAGE,
    TournamentBP,
)

from gem5.components.boards.simple_board import SimpleBoard
from gem5.components.cachehierarchies.classic.private_l1_shared_l2_cache_hierarchy import PrivateL1SharedL2CacheHierarchy
from gem5.components.memory.single_channel import SingleChannelDDR3_1600
from gem5.components.processors.cpu_types import CPUTypes
from gem5.components.processors.simple_processor import SimpleProcessor
from gem5.isas import ISA
from gem5.resources.resource import BinaryResource
from gem5.simulate.simulator import Simulator

parser = argparse.ArgumentParser()
parser.add_argument("--cpu", choices=("o3", "timing", "atomic"), required=True)
parser.add_argument(
    "--bp",
    choices=("local", "tournament", "ltage", "bimode"),
    default="local",
)
parser.add_argument("--binary", required=True)
parser.add_argument("--stu", action="store_true")
parser.add_argument("--window", type=int, default=100000)
parser.add_argument("args", nargs="*")
options = parser.parse_args()

cpu_types = {
    "o3": CPUTypes.O3,
    "timing": CPUTypes.TIMING,
    "atomic": CPUTypes.ATOMIC,
}
processor = SimpleProcessor(
    cpu_type=cpu_types[options.cpu], isa=ISA.X86, num_cores=1
)
if options.cpu == "o3":
    branch_predictors = {
        "local": LocalBP,
        "tournament": TournamentBP,
        "ltage": LTAGE,
        "bimode": BiModeBP,
    }
    processor.get_cores()[0].core.branchPred = branch_predictors[options.bp]()

class StuSimpleBoard(SimpleBoard):
    def _connect_things(self):
        super()._connect_things()
        if options.stu:
            self.stu = SecurityTelemetryUnit(
                cpu=self.get_processor().get_cores()[0].core,
                cache=self.get_cache_hierarchy().l1dcaches[0],
                predictor=self.get_processor().get_cores()[0].core.branchPred,
                process=self.get_processor().get_cores()[0].core.workload[0],
                window_size=options.window,
                output_file=f"{m5.options.outdir}/stu-stream.jsonl",
            )

board = StuSimpleBoard(
    clk_freq="3GHz",
    processor=processor,
    memory=SingleChannelDDR3_1600(size="2GiB"),
    cache_hierarchy=PrivateL1SharedL2CacheHierarchy(
        l1d_size="64KiB", l1i_size="64KiB", l2_size="8MiB"
    ),
)
board.set_se_binary_workload(
    BinaryResource(local_path=options.binary), arguments=options.args
)
if options.stu and options.cpu != "o3":
    parser.error("--stu requires --cpu o3")
Simulator(board=board).run()
