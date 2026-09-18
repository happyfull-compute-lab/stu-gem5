#include "stu/security_telemetry_unit.hh"

#include "cpu/o3/dyn_inst.hh"
#include "cpu/o3/commit.hh"
#include "cpu/o3/iew.hh"
#include "cpu/o3/cpu.hh"
#include "mem/cache/base.hh"
#include "sim/cur_tick.hh"
#include "sim/sim_exit.hh"

namespace gem5
{

template <class T, class Arg>
class ExplicitProbeListener : public ProbeListenerArgBase<Arg>
{
    T *object;
    void (T::*function)(const Arg &);

  public:
    ExplicitProbeListener(T *obj, ProbeManager *manager, const std::string &name,
                          void (T::*func)(const Arg &))
        : ProbeListenerArgBase<Arg>(manager, name), object(obj), function(func)
    {}

    void notify(const Arg &arg) override { (object->*function)(arg); }
};

SecurityTelemetryUnit::SecurityTelemetryUnit(
        const SecurityTelemetryUnitParams &params)
    : SimObject(params), windowSize(params.window_size),
      outputFile(params.output_file), window(0), startTick(0), committed(0),
      totalCommitted(0),
      cleanInvalid(0), squashEvents(0), squashedIssued(0),
      branchMispredicts(0), condIncorrect(0), l1dHits(0), l1dMisses(0),
      firstFlushTick(MaxTick), cpuManager(params.cpu->getProbeManager()),
      cacheManager(params.cache->getProbeManager()),
      predictorManager(params.predictor->getProbeManager()),
      processManager(params.process->getProbeManager()), firstCloneTick(MaxTick),
      cloneSyscalls(0), setuidSyscalls(0), otherSyscalls(0),
      cloneReturns(0), setuidReturns(0), otherReturns(0), faults(0)
{
    stream.open(outputFile, std::ios::out | std::ios::trunc);
    if (!stream.is_open())
        fatal("SecurityTelemetryUnit cannot open %s\n", outputFile);
    registerExitCallback([this]() { onExit(); });
}

SecurityTelemetryUnit::~SecurityTelemetryUnit()
{
    if (committed)
        emitWindow();
    stream.flush();
}

void
SecurityTelemetryUnit::regProbeListeners()
{
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        uint64_t>(this, cpuManager, "CommittedInst", &SecurityTelemetryUnit::onRetired));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        uint64_t>(this, cpuManager, "CommitBranchMispredict", &SecurityTelemetryUnit::onCount));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        uint64_t>(this, predictorManager, "Misses", &SecurityTelemetryUnit::onCondIncorrect));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        SyscallProbeArg>(this, processManager, "SyscallEntry",
                         &SecurityTelemetryUnit::onSyscallEntry));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        SyscallProbeArg>(this, processManager, "SyscallReturn",
                         &SecurityTelemetryUnit::onSyscallReturn));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        uint64_t>(this, processManager, "Fault",
                  &SecurityTelemetryUnit::onFault));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        o3::DynInstConstPtr>(this, cpuManager, "SquashedIssued", &SecurityTelemetryUnit::onSquashedIssued));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        CacheAccessProbeArg>(this, cacheManager, "Hit", &SecurityTelemetryUnit::onHit));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        CacheAccessProbeArg>(this, cacheManager, "Miss", &SecurityTelemetryUnit::onMiss));
    listeners.push_back(new ExplicitProbeListener<SecurityTelemetryUnit,
        PacketPtr>(this, cacheManager, "CleanInvalidReq", &SecurityTelemetryUnit::onCleanInvalid));
}

void SecurityTelemetryUnit::onRetired(const uint64_t &count)
{
    committed += count;
    totalCommitted += count;
    if (committed >= windowSize)
        emitWindow();
}
void SecurityTelemetryUnit::onSquash(const o3::DynInstConstPtr &) { squashEvents++; }
void SecurityTelemetryUnit::onSquashedIssued(const o3::DynInstConstPtr &) { squashedIssued++; }
void SecurityTelemetryUnit::onMispredict(const o3::DynInstConstPtr &) { branchMispredicts++; }
void SecurityTelemetryUnit::onCount(const uint64_t &count) {
    branchMispredicts += count;
    squashEvents += count;
}
void SecurityTelemetryUnit::onCondIncorrect(const uint64_t &count) { condIncorrect += count; }
void SecurityTelemetryUnit::onHit(const CacheAccessProbeArg &arg) {
    if (!arg.pkt->req->isCacheMaintenance() &&
        !arg.pkt->cmd.isHWPrefetch() &&
        (arg.pkt->isRead() || arg.pkt->isWrite()))
        l1dHits++;
}
void SecurityTelemetryUnit::onMiss(const CacheAccessProbeArg &arg) {
    if (!arg.pkt->req->isCacheMaintenance() &&
        !arg.pkt->cmd.isHWPrefetch() &&
        (arg.pkt->isRead() || arg.pkt->isWrite()))
        l1dMisses++;
}
void SecurityTelemetryUnit::onCleanInvalid(const PacketPtr &) {
    cleanInvalid++;
    if (firstFlushTick == MaxTick)
        firstFlushTick = curTick();
}

void SecurityTelemetryUnit::onSyscallEntry(const SyscallProbeArg &arg)
{
    if (arg.number == 56) {
        cloneSyscalls++;
        if (firstCloneTick == MaxTick)
            firstCloneTick = curTick();
    } else if (arg.number == 105) {
        setuidSyscalls++;
    } else {
        otherSyscalls++;
    }
}

void SecurityTelemetryUnit::onSyscallReturn(const SyscallProbeArg &arg)
{
    if (arg.number == 56)
        cloneReturns++;
    else if (arg.number == 105)
        setuidReturns++;
    else
        otherReturns++;
}

void SecurityTelemetryUnit::onFault(const uint64_t &count)
{
    faults += count;
}

void SecurityTelemetryUnit::resetWindow()
{
    startTick = curTick();
    committed = cleanInvalid = squashEvents = squashedIssued = 0;
    branchMispredicts = condIncorrect = l1dHits = l1dMisses = 0;
    cloneSyscalls = setuidSyscalls = otherSyscalls = 0;
    cloneReturns = setuidReturns = otherReturns = 0;
}

void SecurityTelemetryUnit::emitWindow()
{
    const double scale = 1000000.0 / (committed ? committed : 1);
    stream << "{\"window\":" << window++
           << ",\"start_tick\":" << startTick
           << ",\"end_tick\":" << curTick()
           << ",\"committed\":" << committed
           << ",\"cleanInvalid\":" << cleanInvalid
           << ",\"squashEvents\":" << squashEvents
           << ",\"squashedIssued\":" << squashedIssued
           << ",\"branchMispredicts\":" << branchMispredicts
           << ",\"condIncorrect\":" << condIncorrect
           << ",\"l1dHits\":" << l1dHits
           << ",\"l1dMisses\":" << l1dMisses
           << ",\"syscalls\":{\"clone\":" << cloneSyscalls
           << ",\"setuid\":" << setuidSyscalls
           << ",\"other\":" << otherSyscalls << "}"
           << ",\"syscallReturns\":{\"clone\":" << cloneReturns
           << ",\"setuid\":" << setuidReturns
           << ",\"other\":" << otherReturns << "}"
           << ",\"faults\":" << faults
           << ",\"rates\":{\"cleanInvalidPerMinst\":"
           << cleanInvalid * scale
           << ",\"squashedIssuedPerMinst\":" << squashedIssued * scale
           << ",\"mispredRate\":"
           << (committed ? condIncorrect / double(committed) : 0.0)
           << ",\"l1dMissRate\":"
           << (l1dHits + l1dMisses ?
                l1dMisses / double(l1dHits + l1dMisses) : 0.0)
           << ",\"cloneSyscallsPerMinst\":" << cloneSyscalls * scale
           << ",\"setuidSyscallsPerMinst\":" << setuidSyscalls * scale
           << "},\"firstFlushTick\":"
           << (firstFlushTick == MaxTick ? 0 : firstFlushTick)
           << ",\"firstCloneTick\":"
           << (firstCloneTick == MaxTick ? 0 : firstCloneTick) << "}\n";
    stream.flush();
    resetWindow();
}

void SecurityTelemetryUnit::onExit()
{
    if (committed || cleanInvalid || squashEvents || squashedIssued ||
        branchMispredicts || condIncorrect || l1dHits || l1dMisses ||
        faults)
        emitWindow();
    stream.flush();
}

} // namespace gem5
