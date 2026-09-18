from m5.SimObject import SimObject
from m5.params import Param, Int, String
from m5.proxy import Parent

class SecurityTelemetryUnit(SimObject):
    type = "SecurityTelemetryUnit"
    cxx_class = "gem5::SecurityTelemetryUnit"
    cxx_header = "stu/security_telemetry_unit.hh"

    cpu = Param.SimObject(Parent.any, "O3 CPU owning commit probes")
    cache = Param.SimObject(Parent.any, "L1D cache owning cache probes")
    predictor = Param.SimObject(Parent.any, "Branch predictor owning miss probe")
    process = Param.SimObject(Parent.any, "SE process owning syscall probes")
    window_size = Param.Int(100000, "Committed instructions per window")
    output_file = Param.String("stu-stream.jsonl", "JSONL telemetry output")
