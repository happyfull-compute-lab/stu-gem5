#ifndef __STU_SECURITY_TELEMETRY_UNIT_HH__
#define __STU_SECURITY_TELEMETRY_UNIT_HH__

#include <fstream>

#include "mem/cache/cache_probe_arg.hh"
#include "sim/syscall_probe.hh"
#include "cpu/o3/dyn_inst_ptr.hh"
#include "params/SecurityTelemetryUnit.hh"
#include "sim/probe/probe.hh"
#include "sim/sim_object.hh"

namespace gem5
{

class SecurityTelemetryUnit : public SimObject
{
  private:
    ProbeManager *cpuManager;
    ProbeManager *cacheManager;
    ProbeManager *predictorManager;
    ProbeManager *processManager;
    const int windowSize;
    const std::string outputFile;
    std::ofstream stream;
    uint64_t window;
    uint64_t startTick;
    uint64_t committed;
    uint64_t totalCommitted;
    uint64_t cleanInvalid;
    uint64_t squashEvents;
    uint64_t squashedIssued;
    uint64_t branchMispredicts;
    uint64_t condIncorrect;
    uint64_t l1dHits;
    uint64_t l1dMisses;
    Tick firstFlushTick;
    Tick firstCloneTick;
    uint64_t cloneSyscalls;
    uint64_t setuidSyscalls;
    uint64_t otherSyscalls;
    uint64_t cloneReturns;
    uint64_t setuidReturns;
    uint64_t otherReturns;
    uint64_t faults;

    std::vector<ProbeListener *> listeners;

    void onRetired(const uint64_t &count);
    void onSquash(const o3::DynInstConstPtr &inst);
    void onSquashedIssued(const o3::DynInstConstPtr &inst);
    void onMispredict(const o3::DynInstConstPtr &inst);
    void onCount(const uint64_t &count);
    void onCondIncorrect(const uint64_t &count);
    void onExit();
    void onHit(const CacheAccessProbeArg &arg);
    void onMiss(const CacheAccessProbeArg &arg);
    void onCleanInvalid(const PacketPtr &pkt);
    void onSyscallEntry(const SyscallProbeArg &arg);
    void onSyscallReturn(const SyscallProbeArg &arg);
    void onFault(const uint64_t &count);
    void emitWindow();
    void resetWindow();

  public:
    SecurityTelemetryUnit(const SecurityTelemetryUnitParams &params);
    ~SecurityTelemetryUnit() override;
    void regProbeListeners() override;
};

} // namespace gem5

#endif
