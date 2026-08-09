// SPDX-License-Identifier: MIT
//
// fleetsim's seventh live master: a REAL DNP3 master (opendnp3 3.1.2) driving
// the simulated outstation that `modules/fleetsim`'s live test binds.
//
// ── why this one is C++ and the other six are Python ─────────────────────
//
// Every other master in this lane is a pip-installable library. DNP3 has none
// that works: `pydnp3` last released in 2018 and never published a Linux
// wheel, `dnp3-python`'s newest wheel is cp310 while the guest is Python 3.13,
// Debian packages no DNP3 stack in any suite, and the actively maintained
// successor (stepfunc/dnp3) ships a proprietary non-commercial licence. What
// is left is `opendnp3` itself: Apache-2.0, archived 2022-05-18, and still
// compiling clean on a 2026 toolchain. It has no scriptable master binary —
// `master-demo` is an interactive REPL — so the test choreography has to be a
// program.
//
// That is NOT a sibling implementation. Every DNP3 byte on the wire is
// composed and parsed by opendnp3's own stack; nothing below encodes a link
// frame, computes a CRC, or reads an object header. The only protocol-aware
// code here is the capture tap's frame *delimiting*, which reads the link
// header's length octet purely so the recording is a list of frames instead of
// a list of TCP segments — the same thing the Modbus tap does with the MBAP
// length field, and it grades nothing.
//
// ── what it grades, and why none of the marks is an echo ─────────────────
//
// The master reads the fixture, checks every point in its own number domain,
// and writes its findings back through DNP3's own control direction: g41v1
// analog output blocks for the integers and g12v1 control relay output blocks
// for the booleans. It deliberately never writes back a value it just read —
// an echo is the exact inverse of the read, so a codec that is wrong in both
// directions round-trips clean and hides inside it. Instead:
//
//   * a magic constant, so "somebody wrote here" is distinguishable from zero;
//   * counts of checks run and checks failed;
//   * a bitmap packed from eight separate binary decodes;
//   * a sum over three analog decodes;
//   * a difference across two DIFFERENT type decodes (g20 Counter, unsigned,
//     minus g30 Analog, signed) which no echo of either operand can produce;
//   * a value taken out of its native domain (a g30v5 short float scaled x100
//     into an integer) and then differenced against a signed integer decode;
//   * a checksum over the WHOLE integrity poll, folding each point's index and
//     the DNP3 group opendnp3 itself dispatched it to — so a superset, a
//     missing header, or right-values-under-the-wrong-type all fail it;
//   * two refusal codes the OUTSTATION chose and opendnp3 reported
//     (OUT_OF_RANGE for a bounded analog output, NOT_SUPPORTED for a control
//     against an index that does not exist);
//   * a bitmap of the IIN bits opendnp3 saw across the run, which is the
//     application header rather than the object data — a different channel;
//   * and a pass bit written in BOTH outcomes, so "a master ran and is
//     unhappy" is distinguishable from "no master ran".
//
// ── output contract ──────────────────────────────────────────────────────
//
// Human-readable progress on stdout, then the capture between
// FLEETSIM_CAPTURE_BEGIN/END, then DNP3_MASTER_DONE, then DNP3_MASTER_OK
// (exit 0) or DNP3_MASTER_FAIL (exit 1). `scripts/vm/run.sh` requires
// DNP3_MASTER_DONE — *presence*, never the grade. The grade is the Zig
// suite's job: it reads the verdict block back out of the device.
//
// Usage: fleetsim-dnp3-master <device-host> <device-port> <wait-seconds>

#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/IMasterApplication.h>
#include <opendnp3/master/ISOEHandler.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace opendnp3;

// ── the fixture this master is written against ───────────────────────────
//
// Mirrors `test "live: a real DNP3 master drives a simulated outstation"` in
// modules/fleetsim/src/root.zig. Kept as named constants so a mismatch is a
// counted failure with a printed number, not a silent pass.
static const bool kBinaries[8] = {true, false, true, true, false, true, false, true};
static const int32_t kAnalogInt[3] = {12345, -6789, 1000};
static const double kAnalogFloat = 21.5; // analog input 3, g30v5 short float
static const uint32_t kCounters[2] = {100000, 777};
static const size_t kBinaryOutputs = 4;
static const size_t kAnalogOutputs = 12;

// Verdict channel. Analog output points 0..10 carry the integer marks; the
// bounded refusal target is the last analog output; the pass bit and the
// fault-observed bit are control relay output blocks.
enum : uint16_t
{
    kAoMagic = 0,
    kAoChecks = 1,
    kAoFailures = 2,
    kAoBinaryBitmap = 3,
    kAoAnalogSum = 4,
    kAoCounterMinusAnalog = 5,
    kAoFloatMinusAnalog = 6,
    kAoPollChecksum = 7,
    kAoOutOfRangeCode = 8,
    kAoNotSupportedCode = 9,
    kAoIinMask = 10,
    kAoBoundedTarget = 11, // min=0 max=100 on the device; a big write is refused
};
enum : uint16_t
{
    kBoPass = 0,
    kBoTroubleSeen = 1,
    kBoAbsentIndex = 9, // >= kBinaryOutputs, so the device refuses it
};

static const int32_t kMagic = 53619;  // 0xD173
static const int32_t kChecksumMod = 30011;
static const int32_t kOutOfRangeWrite = 999999;

// ── tiny helpers ─────────────────────────────────────────────────────────

static void say(const std::string& s)
{
    std::fputs(s.c_str(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

static std::string hexOf(const std::vector<uint8_t>& b)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (uint8_t c : b)
    {
        s.push_back(d[c >> 4]);
        s.push_back(d[c & 0xF]);
    }
    return s;
}

static std::string jsonEscape(const std::string& s)
{
    std::string o;
    for (char c : s)
    {
        if (c == '"' || c == '\\')
        {
            o.push_back('\\');
            o.push_back(c);
        }
        else if (c == '\n')
        {
            o += "\\n";
        }
        else
        {
            o.push_back(c);
        }
    }
    return o;
}

// ── the capture tap ──────────────────────────────────────────────────────
//
// A one-connection TCP relay. opendnp3 connects here; here connects to the
// simulated device. Nothing is modified in flight: this is a recorder, not a
// proxy with opinions. Both directions are reassembled into whole DNP3 link
// frames from the link header's own length octet, so the frozen vectors are
// frames rather than packets — TCP segmentation must not be able to change
// what gets recorded.
//
// Frame layout (IEEE 1815 §9.2.4), used ONLY for delimiting: 0x05 0x64, then
// LEN counting CTRL + DEST(2) + SRC(2) + user data, then a 2-octet header
// CRC, then the user data in 16-octet blocks each followed by its own 2-octet
// CRC. No CRC is computed or checked here — opendnp3 does that, and it is the
// side whose opinion counts.
static size_t linkFrameLen(const uint8_t* p, size_t avail)
{
    if (avail < 3) return 0;
    if (p[0] != 0x05 || p[1] != 0x64) return SIZE_MAX; // desynchronised
    const size_t len = p[2];
    if (len < 5) return SIZE_MAX;
    const size_t user = len - 5;
    const size_t blocks = (user + 15) / 16;
    return 10 + user + 2 * blocks;
}

class Tap
{
public:
    Tap() = default;

    bool connectUpstream(const std::string& host, uint16_t port, int waitSeconds)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(waitSeconds);
        while (std::chrono::steady_clock::now() < deadline)
        {
            int s = ::socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) return false;
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port = htons(port);
            if (::inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1)
            {
                ::close(s);
                return false;
            }
            if (::connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0)
            {
                int one = 1;
                ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                up_ = s;
                return true;
            }
            ::close(s);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        return false;
    }

    bool listenLocal()
    {
        lsock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (lsock_ < 0) return false;
        int one = 1;
        ::setsockopt(lsock_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (::bind(lsock_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        if (::listen(lsock_, 1) != 0) return false;
        socklen_t sl = sizeof(a);
        if (::getsockname(lsock_, reinterpret_cast<sockaddr*>(&a), &sl) != 0) return false;
        port_ = ntohs(a.sin_port);
        return true;
    }

    uint16_t port() const { return port_; }

    void start()
    {
        accepter_ = std::thread([this] {
            sockaddr_in peer{};
            socklen_t pl = sizeof(peer);
            int d = ::accept(lsock_, reinterpret_cast<sockaddr*>(&peer), &pl);
            if (d < 0) return;
            int one = 1;
            ::setsockopt(d, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            down_ = d;
            pumps_.emplace_back([this] { pump(down_, up_, true); });
            pumps_.emplace_back([this] { pump(up_, down_, false); });
        });
    }

    // Frames seen since the previous drain.
    void drain(std::vector<std::vector<uint8_t>>& tx, std::vector<std::vector<uint8_t>>& rx)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        std::lock_guard<std::mutex> g(m_);
        tx.assign(txFrames_.begin() + static_cast<long>(txTaken_), txFrames_.end());
        rx.assign(rxFrames_.begin() + static_cast<long>(rxTaken_), rxFrames_.end());
        txTaken_ = txFrames_.size();
        rxTaken_ = rxFrames_.size();
    }

    void stop()
    {
        stopped_ = true;
        if (up_ >= 0) ::shutdown(up_, SHUT_RDWR);
        if (down_ >= 0) ::shutdown(down_, SHUT_RDWR);
        if (lsock_ >= 0) ::close(lsock_);
        if (accepter_.joinable()) accepter_.join();
        for (auto& t : pumps_)
            if (t.joinable()) t.join();
        if (up_ >= 0) ::close(up_);
        if (down_ >= 0) ::close(down_);
        up_ = down_ = lsock_ = -1;
    }

private:
    void pump(int src, int dst, bool isTx)
    {
        std::vector<uint8_t> buf;
        uint8_t chunk[4096];
        while (!stopped_)
        {
            ssize_t n = ::recv(src, chunk, sizeof(chunk), 0);
            if (n <= 0) break;
            {
                std::lock_guard<std::mutex> g(m_);
                buf.insert(buf.end(), chunk, chunk + n);
                size_t i = 0;
                while (i < buf.size())
                {
                    const size_t need = linkFrameLen(buf.data() + i, buf.size() - i);
                    if (need == SIZE_MAX)
                    {
                        i = buf.size(); // desync: drop rather than mis-frame
                        break;
                    }
                    if (need == 0 || i + need > buf.size()) break;
                    std::vector<uint8_t> f(buf.begin() + static_cast<long>(i),
                                           buf.begin() + static_cast<long>(i + need));
                    (isTx ? txFrames_ : rxFrames_).push_back(std::move(f));
                    i += need;
                }
                buf.erase(buf.begin(), buf.begin() + static_cast<long>(i));
            }
            if (::send(dst, chunk, static_cast<size_t>(n), 0) < 0) break;
        }
        ::shutdown(dst, SHUT_WR);
    }

    int up_ = -1, down_ = -1, lsock_ = -1;
    uint16_t port_ = 0;
    std::atomic<bool> stopped_{false};
    std::thread accepter_;
    std::vector<std::thread> pumps_;
    std::mutex m_;
    std::vector<std::vector<uint8_t>> txFrames_, rxFrames_;
    size_t txTaken_ = 0, rxTaken_ = 0;
};

// ── what opendnp3 decoded ────────────────────────────────────────────────

struct Poll
{
    std::vector<std::pair<uint16_t, bool>> binaries;
    std::vector<std::pair<uint16_t, double>> analogs;
    std::vector<std::pair<uint16_t, uint32_t>> counters;
    std::vector<std::pair<uint16_t, bool>> binaryOutputs;
    std::vector<std::pair<uint16_t, double>> analogOutputs;
    // (index * 7 + group) folded over every point in the response, where the
    // group is the one opendnp3's own dispatch chose by handing the values to
    // a particular typed overload.
    int64_t checksum = 0;

    void fold(uint16_t index, int32_t group) { checksum += static_cast<int64_t>(index) * 7 + group; }
};

class Collector : public ISOEHandler
{
public:
    void BeginFragment(const ResponseInfo&) override {}

    void EndFragment(const ResponseInfo& info) override
    {
        if (info.unsolicited || !info.fin) return;
        {
            std::lock_guard<std::mutex> g(m_);
            done_ = true;
        }
        cv_.notify_all();
    }

    void Process(const HeaderInfo&, const ICollection<Indexed<Binary>>& v) override
    {
        v.ForeachItem([this](const Indexed<Binary>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.binaries.emplace_back(x.index, x.value.value);
            poll_.fold(x.index, 1);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<DoubleBitBinary>>& v) override
    {
        v.ForeachItem([this](const Indexed<DoubleBitBinary>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.fold(x.index, 3);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<Analog>>& v) override
    {
        v.ForeachItem([this](const Indexed<Analog>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.analogs.emplace_back(x.index, x.value.value);
            poll_.fold(x.index, 30);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<Counter>>& v) override
    {
        v.ForeachItem([this](const Indexed<Counter>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.counters.emplace_back(x.index, x.value.value);
            poll_.fold(x.index, 20);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<FrozenCounter>>& v) override
    {
        v.ForeachItem([this](const Indexed<FrozenCounter>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.fold(x.index, 21);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryOutputStatus>>& v) override
    {
        v.ForeachItem([this](const Indexed<BinaryOutputStatus>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.binaryOutputs.emplace_back(x.index, x.value.value);
            poll_.fold(x.index, 10);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogOutputStatus>>& v) override
    {
        v.ForeachItem([this](const Indexed<AnalogOutputStatus>& x) {
            std::lock_guard<std::mutex> g(m_);
            poll_.analogOutputs.emplace_back(x.index, x.value.value);
            poll_.fold(x.index, 40);
        });
    }
    void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>&) override {}
    void Process(const HeaderInfo&, const ICollection<DNPTime>&) override {}

    void reset()
    {
        std::lock_guard<std::mutex> g(m_);
        poll_ = Poll{};
        done_ = false;
    }

    bool wait(int seconds)
    {
        std::unique_lock<std::mutex> lk(m_);
        return cv_.wait_for(lk, std::chrono::seconds(seconds), [this] { return done_; });
    }

    Poll snapshot()
    {
        std::lock_guard<std::mutex> g(m_);
        return poll_;
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool done_ = false;
    Poll poll_;
};

// Captures the application header's IIN, which is a channel the object data
// cannot reach: IIN1.6 (device trouble) is what the scheduled fault raises and
// IIN1.7 (device restart) is what a fresh outstation raises.
// `DefaultMasterApplication` is `final` and its `OnReceiveIIN` is `final` too,
// so IMasterApplication has to be implemented directly. Only `Now()` is pure;
// everything else has a do-nothing default in the interface.
class App : public IMasterApplication
{
public:
    UTCTimestamp Now() override
    {
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
        return UTCTimestamp(static_cast<uint64_t>(ms));
    }

    void OnReceiveIIN(const IINField& iin) override
    {
        std::lock_guard<std::mutex> g(m_);
        lsb_ |= iin.LSB;
        msb_ |= iin.MSB;
        phaseLsb_ |= iin.LSB;
    }

    void resetPhase()
    {
        std::lock_guard<std::mutex> g(m_);
        phaseLsb_ = 0;
    }
    uint8_t phaseLsb()
    {
        std::lock_guard<std::mutex> g(m_);
        return phaseLsb_;
    }
    uint8_t lsb()
    {
        std::lock_guard<std::mutex> g(m_);
        return lsb_;
    }

    static std::shared_ptr<App> Create() { return std::make_shared<App>(); }

private:
    std::mutex m_;
    uint8_t lsb_ = 0, msb_ = 0, phaseLsb_ = 0;
};

// ── command plumbing ─────────────────────────────────────────────────────

struct CmdOutcome
{
    bool completed = false;
    TaskCompletion summary = TaskCompletion::FAILURE_NO_COMMS;
    CommandStatus status = CommandStatus::UNDEFINED;
};

template<class T>
static CmdOutcome operateOne(IMaster& master, const T& cmd, uint16_t index, int seconds)
{
    auto m = std::make_shared<std::mutex>();
    auto cv = std::make_shared<std::condition_variable>();
    auto out = std::make_shared<CmdOutcome>();

    master.DirectOperate(cmd, index, [m, cv, out](const ICommandTaskResult& r) {
        {
            std::lock_guard<std::mutex> g(*m);
            out->summary = r.summary;
            r.ForeachItem([&out](const CommandPointResult& p) { out->status = p.status; });
            out->completed = true;
        }
        cv->notify_all();
    });

    std::unique_lock<std::mutex> lk(*m);
    cv->wait_for(lk, std::chrono::seconds(seconds), [&out] { return out->completed; });
    return *out;
}

// ── main ─────────────────────────────────────────────────────────────────

struct Record
{
    std::string op;
    std::vector<std::vector<uint8_t>> tx, rx;
    std::string decoded;
};

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        say("usage: fleetsim-dnp3-master <host> <port> <wait-seconds>");
        say("DNP3_MASTER_FAIL");
        return 1;
    }
    const std::string host = argv[1];
    const uint16_t port = static_cast<uint16_t>(std::atoi(argv[2]));
    const int waitSeconds = std::atoi(argv[3]);

    say("master: opendnp3 3.1.2 (licence: Apache-2.0) -> " + host + ":" + std::to_string(port));

    Tap tap;
    if (!tap.listenLocal())
    {
        say("master: could not bind the capture tap");
        say("DNP3_MASTER_FAIL");
        return 1;
    }
    if (!tap.connectUpstream(host, port, waitSeconds))
    {
        say("master: device never accepted a connection within " + std::to_string(waitSeconds) + "s");
        say("DNP3_MASTER_FAIL");
        return 1;
    }
    tap.start();
    say("master: tap listening on 127.0.0.1:" + std::to_string(tap.port()) + ", upstream connected");

    std::vector<Record> records;
    std::vector<std::string> failures;
    int checks = 0;
    auto check = [&](bool ok, const std::string& what) {
        ++checks;
        if (!ok) failures.push_back(what);
        return ok;
    };

    // ── stack ────────────────────────────────────────────────────────────
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto channel = manager.AddTCPClient("tcpclient", levels::NORMAL, ChannelRetry::Default(),
                                        {IPEndpoint("127.0.0.1", tap.port())}, "0.0.0.0",
                                        PrintingChannelListener::Create());

    MasterStackConfig cfg;
    cfg.master.responseTimeout = TimeDuration::Seconds(5);
    cfg.master.disableUnsolOnStartup = true;
    cfg.master.timeSyncMode = TimeSyncMode::None;
    // The startup integrity scan is left ON: it is part of what a real master
    // does, and the recording is more honest for containing it.
    cfg.link.LocalAddr = 1;
    cfg.link.RemoteAddr = 10;

    auto soe = std::make_shared<Collector>();
    auto app = App::Create();
    auto master = channel->AddMaster("master", soe, app, cfg);

    soe->reset();
    app->resetPhase();
    master->Enable();

    // ── phase 1: the startup handshake and the first integrity poll ──────
    if (!soe->wait(30))
    {
        say("master: no integrity response within 30s of enabling");
        tap.stop();
        say("DNP3_MASTER_FAIL");
        return 1;
    }
    Poll first = soe->snapshot();
    const uint8_t iinStartup = app->phaseLsb();
    {
        Record r;
        r.op = "startup handshake + integrity poll (class 3/2/1/0)";
        tap.drain(r.tx, r.rx);
        r.decoded = "binaries=" + std::to_string(first.binaries.size())
            + " analogs=" + std::to_string(first.analogs.size())
            + " counters=" + std::to_string(first.counters.size())
            + " binary_outputs=" + std::to_string(first.binaryOutputs.size())
            + " analog_outputs=" + std::to_string(first.analogOutputs.size())
            + " iin1=0x" + std::to_string(static_cast<int>(iinStartup));
        records.push_back(std::move(r));
    }

    // ── grade the first poll ─────────────────────────────────────────────
    check(first.binaries.size() == 8, "binary input count");
    int32_t bitmap = 0;
    for (const auto& b : first.binaries)
        if (b.second && b.first < 16) bitmap |= (1 << b.first);
    int32_t wantBitmap = 0;
    for (int i = 0; i < 8; ++i)
        if (kBinaries[i]) wantBitmap |= (1 << i);
    check(bitmap == wantBitmap, "binary bitmap: got " + std::to_string(bitmap));

    check(first.analogs.size() == 4, "analog input count");
    double a0 = 0, a1 = 0, a2 = 0, a3 = 0;
    for (const auto& a : first.analogs)
    {
        if (a.first == 0) a0 = a.second;
        if (a.first == 1) a1 = a.second;
        if (a.first == 2) a2 = a.second;
        if (a.first == 3) a3 = a.second;
    }
    check(a0 == kAnalogInt[0], "analog[0]: got " + std::to_string(a0));
    check(a1 == kAnalogInt[1], "analog[1]: got " + std::to_string(a1));
    check(a2 == kAnalogInt[2], "analog[2]: got " + std::to_string(a2));
    check(std::fabs(a3 - kAnalogFloat) < 1e-6, "analog[3] short float: got " + std::to_string(a3));

    check(first.counters.size() == 2, "counter count");
    uint32_t c0 = 0, c1 = 0;
    for (const auto& c : first.counters)
    {
        if (c.first == 0) c0 = c.second;
        if (c.first == 1) c1 = c.second;
    }
    check(c0 == kCounters[0], "counter[0]: got " + std::to_string(c0));
    check(c1 == kCounters[1], "counter[1]: got " + std::to_string(c1));

    check(first.binaryOutputs.size() == kBinaryOutputs, "binary output status count");
    bool allBoClear = true;
    for (const auto& b : first.binaryOutputs)
        if (b.second) allBoClear = false;
    check(allBoClear, "binary outputs start clear");

    check(first.analogOutputs.size() == kAnalogOutputs, "analog output status count");
    bool allAoZero = true;
    for (const auto& a : first.analogOutputs)
        if (a.second != 0) allAoZero = false;
    check(allAoZero, "analog outputs start zero");

    // IIN1.6 must be CLEAR before the scheduled fault; IIN1.7 is expected,
    // because a freshly constructed outstation really has just restarted.
    const bool troubleBefore = (iinStartup & 0x40) != 0;
    const bool restartSeen = (iinStartup & 0x80) != 0;
    check(!troubleBefore, "IIN1.6 clear before the fault");
    check(restartSeen, "IIN1.7 set on a fresh outstation");

    const int32_t pollChecksum = static_cast<int32_t>(first.checksum % kChecksumMod);
    const int32_t analogSum = static_cast<int32_t>(a0 + a1 + a2);
    const int32_t floatX100 = static_cast<int32_t>(std::llround(a3 * 100.0));
    const int32_t counterMinusAnalog = static_cast<int32_t>(static_cast<int64_t>(c0) - static_cast<int64_t>(a0));
    const int32_t floatMinusAnalog = floatX100 - static_cast<int32_t>(a1);

    say("master: first poll graded — bitmap=" + std::to_string(bitmap) + " analog_sum="
        + std::to_string(analogSum) + " float_x100=" + std::to_string(floatX100)
        + " counter_minus_analog=" + std::to_string(counterMinusAnalog)
        + " float_minus_analog=" + std::to_string(floatMinusAnalog)
        + " poll_checksum=" + std::to_string(pollChecksum));

    // ── phase 2: poll again on the far side of the scheduled fault ───────
    //
    // The device raises `trouble` at simulated t=15 s and the live test runs
    // for 60 s, so a second integrity poll after ~20 s of wall clock lands
    // past it. IIN1.6 is what the outstation says about itself; it is not
    // derivable from any point value.
    say("master: waiting out the device's scheduled fault (t=15s) before polling again");
    std::this_thread::sleep_for(std::chrono::seconds(20));
    soe->reset();
    app->resetPhase();
    master->ScanClasses(ClassField::AllClasses(), soe);
    const bool second = soe->wait(20);
    const uint8_t iinAfter = app->phaseLsb();
    {
        Record r;
        r.op = "integrity poll after the scheduled fault";
        tap.drain(r.tx, r.rx);
        r.decoded = "responded=" + std::string(second ? "yes" : "no") + " iin1=0x"
            + std::to_string(static_cast<int>(iinAfter));
        records.push_back(std::move(r));
    }
    check(second, "second integrity poll answered");
    const bool troubleAfter = (iinAfter & 0x40) != 0;
    check(troubleAfter, "IIN1.6 set after the fault");

    int32_t iinMask = 0;
    if (restartSeen) iinMask |= 1;
    if (!troubleBefore) iinMask |= 2;
    if (troubleAfter) iinMask |= 4;

    // ── phase 3: two refusals the OUTSTATION chooses ─────────────────────
    //
    // Neither code is ours: opendnp3 parses the echoed command object's status
    // octet and names it. A device that accepted either would be wrong, and a
    // device that refused with a different code would be caught too.
    auto oor = operateOne(*master, AnalogOutputInt32(kOutOfRangeWrite), kAoBoundedTarget, 15);
    {
        Record r;
        r.op = "direct operate g41v1 " + std::to_string(kOutOfRangeWrite) + " -> analog output "
            + std::to_string(kAoBoundedTarget) + " (bounded 0..100 on the device)";
        tap.drain(r.tx, r.rx);
        r.decoded = "summary=" + std::string(TaskCompletionSpec::to_human_string(oor.summary))
            + " status=" + std::string(CommandStatusSpec::to_human_string(oor.status));
        records.push_back(std::move(r));
    }
    check(oor.status == CommandStatus::OUT_OF_RANGE,
          std::string("bounded analog write refused OUT_OF_RANGE, got ")
              + CommandStatusSpec::to_human_string(oor.status));

    auto uns = operateOne(*master, ControlRelayOutputBlock(OperationType::LATCH_ON), kBoAbsentIndex, 15);
    {
        Record r;
        r.op = "direct operate g12v1 LATCH_ON -> binary output " + std::to_string(kBoAbsentIndex)
            + " (does not exist on the device)";
        tap.drain(r.tx, r.rx);
        r.decoded = "summary=" + std::string(TaskCompletionSpec::to_human_string(uns.summary))
            + " status=" + std::string(CommandStatusSpec::to_human_string(uns.status));
        records.push_back(std::move(r));
    }
    check(uns.status == CommandStatus::NOT_SUPPORTED,
          std::string("absent control index refused NOT_SUPPORTED, got ")
              + CommandStatusSpec::to_human_string(uns.status));

    const int32_t outOfRangeCode = static_cast<int32_t>(oor.status);
    const int32_t notSupportedCode = static_cast<int32_t>(uns.status);

    // ── phase 4: write the marks back through DNP3's control direction ───
    const int32_t failed = static_cast<int32_t>(failures.size());
    const std::vector<std::pair<uint16_t, int32_t>> marks = {
        {kAoMagic, kMagic},
        {kAoChecks, static_cast<int32_t>(checks)},
        {kAoFailures, failed},
        {kAoBinaryBitmap, bitmap},
        {kAoAnalogSum, analogSum},
        {kAoCounterMinusAnalog, counterMinusAnalog},
        {kAoFloatMinusAnalog, floatMinusAnalog},
        {kAoPollChecksum, pollChecksum},
        {kAoOutOfRangeCode, outOfRangeCode},
        {kAoNotSupportedCode, notSupportedCode},
        {kAoIinMask, iinMask},
    };
    bool wroteAll = true;
    for (const auto& mk : marks)
    {
        auto res = operateOne(*master, AnalogOutputInt32(mk.second), mk.first, 15);
        if (res.status != CommandStatus::SUCCESS) wroteAll = false;
        Record r;
        r.op = "direct operate g41v1 " + std::to_string(mk.second) + " -> analog output "
            + std::to_string(mk.first);
        tap.drain(r.tx, r.rx);
        r.decoded = std::string("status=") + CommandStatusSpec::to_human_string(res.status);
        records.push_back(std::move(r));
    }

    // The fault-observed bit, then the pass bit — the pass bit LAST and in
    // BOTH outcomes, so the device carries "a master ran and was unhappy"
    // distinctly from "no master ran".
    {
        auto res = operateOne(*master,
                              ControlRelayOutputBlock(troubleAfter ? OperationType::LATCH_ON
                                                                   : OperationType::LATCH_OFF),
                              kBoTroubleSeen, 15);
        Record r;
        r.op = std::string("direct operate g12v1 ") + (troubleAfter ? "LATCH_ON" : "LATCH_OFF")
            + " -> binary output " + std::to_string(kBoTroubleSeen) + " (fault observed)";
        tap.drain(r.tx, r.rx);
        r.decoded = std::string("status=") + CommandStatusSpec::to_human_string(res.status);
        records.push_back(std::move(r));
        if (res.status != CommandStatus::SUCCESS) wroteAll = false;
    }
    const bool allPassed = failures.empty() && wroteAll;
    {
        auto res = operateOne(*master,
                              ControlRelayOutputBlock(allPassed ? OperationType::LATCH_ON
                                                                : OperationType::LATCH_OFF),
                              kBoPass, 15);
        Record r;
        r.op = std::string("direct operate g12v1 ") + (allPassed ? "LATCH_ON" : "LATCH_OFF")
            + " -> binary output " + std::to_string(kBoPass) + " (pass bit)";
        tap.drain(r.tx, r.rx);
        r.decoded = std::string("status=") + CommandStatusSpec::to_human_string(res.status);
        records.push_back(std::move(r));
    }

    master->Disable();
    manager.Shutdown();
    tap.stop();

    // ── the capture ──────────────────────────────────────────────────────
    say("FLEETSIM_CAPTURE_BEGIN");
    say("{\"master\":\"opendnp3\",\"version\":\"3.1.2\",\"licence\":\"Apache-2.0\"}");
    for (const auto& r : records)
    {
        std::string j = "{\"op\":\"" + jsonEscape(r.op) + "\",\"tx\":[";
        for (size_t i = 0; i < r.tx.size(); ++i)
        {
            if (i) j += ",";
            j += "\"" + hexOf(r.tx[i]) + "\"";
        }
        j += "],\"rx\":[";
        for (size_t i = 0; i < r.rx.size(); ++i)
        {
            if (i) j += ",";
            j += "\"" + hexOf(r.rx[i]) + "\"";
        }
        j += "],\"decoded\":\"" + jsonEscape(r.decoded) + "\"}";
        say(j);
    }
    say("FLEETSIM_CAPTURE_END");

    say("master: verdict magic=" + std::to_string(kMagic) + " checks=" + std::to_string(checks)
        + " failures=" + std::to_string(failed) + " bitmap=" + std::to_string(bitmap)
        + " analog_sum=" + std::to_string(analogSum) + " counter_minus_analog="
        + std::to_string(counterMinusAnalog) + " float_minus_analog="
        + std::to_string(floatMinusAnalog) + " poll_checksum=" + std::to_string(pollChecksum)
        + " out_of_range=" + std::to_string(outOfRangeCode) + " not_supported="
        + std::to_string(notSupportedCode) + " iin_mask=" + std::to_string(iinMask)
        + " pass=" + (allPassed ? "true" : "false"));
    say("DNP3_MASTER_DONE");

    if (!allPassed)
    {
        for (const auto& f : failures)
            say("master: FAILURE " + f);
        if (!wroteAll) say("master: FAILURE not every verdict write was accepted");
        say("DNP3_MASTER_FAIL");
        return 1;
    }
    say("master: " + std::to_string(records.size()) + " operations, all satisfied by opendnp3 3.1.2");
    say("DNP3_MASTER_OK");
    return 0;
}
