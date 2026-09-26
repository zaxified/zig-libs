// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Multithreaded compression (port of lib/compress/zstdmt_compress.c,
//! v1.5.7): `ZSTD_compressStream2` with `ZSTD_c_nbWorkers` of 1 or more.
//!
//! The input is copied into a round buffer and cut into jobs of
//! `targetSectionSize` bytes (a flush or the end cuts a shorter one). Each
//! job is compressed on its own context as a frame of its own whose header
//! is dropped: the first job writes the real header (and carries the
//! dictionary), every later one reloads the tail of the previous job's input
//! (the overlap, `targetPrefixSize`) as a raw-content prefix, starts with its
//! repeat offsets invalidated, and the last one ends the frame. The jobs'
//! outputs are concatenated in order. Two things run serially across jobs,
//! in job order (`ZSTDMT_serialState`): the content checksum and the
//! long-distance matcher, whose window spans the whole round buffer; the
//! sequences it finds for a job are handed to that job's context as
//! external sequences.
//!
//! **The bytes do not depend on the worker count** (from 1 up) nor on the
//! scheduling: how the input is cut into jobs depends only on the calls
//! (the caller must go on calling `flush`/`end` until they return 0, as for
//! libzstd), and a job's bytes only on its input, its prefix, the
//! parameters and the serially made LDM sequences. libzstd runs its serial
//! step in the workers, waiting for its turn; this port runs it on the
//! calling thread when it prepares the job, which is the same order.
//!
//! Threads: a fixed pool of `nb_workers` `std.Thread`s, each with its own
//! compression context, fed through a small queue. Synchronisation is
//! atomics plus the futex of `std.Io` (through the process-global
//! `std.Io.Threaded` instance, whose futex calls are stateless), so the
//! module needs neither libc nor an `Io` from its caller. See SPEC.md,
//! *Multithreading*, for the choice against `workerpool`.
//!
//! With `ZSTD_c_rsyncable` (`Advanced.rsyncable`), a rolling hash over the
//! last 32 input bytes also cuts a job wherever its low bits are all ones
//! (`findSynchronizationPoint`), so that an edit to the input changes the
//! output only up to the next such point.

const std = @import("std");
const builtin = @import("builtin");
const frame = @import("frame.zig");
const params = @import("params.zig");
const ldm = @import("ldm.zig");
const cdict_mod = @import("cdict.zig");
const stream = @import("stream.zig");
const CDict = cdict_mod.CDict;

/// `ZSTDMT_JOBSIZE_MIN`: a frame of at most this many bytes (pledged, or
/// the whole input of a first call that ends it) is compressed on the
/// calling thread even with workers (`ZSTD_CCtx_init_compressStream2`); a
/// smaller `job_size` counts as this.
pub const job_size_min: usize = 512 << 10;
/// `ZSTDMT_JOBSIZE_MAX`, `ZSTDMT_JOBLOG_MAX` (64-bit).
pub const job_size_max: usize = params.job_size_max;
const job_log_max = 30;
const block_size_max = params.block_size_max_abs;
/// A job compresses its input by chunks of this size (for finer progress).
const chunk_size = 4 * block_size_max;
const block_header_size = 3;

/// `RSYNC_LENGTH`: the rolling hash's window.
const rsync_length = 32;
/// `RSYNC_MIN_BLOCK_LOG` (`ZSTD_BLOCKSIZELOG_MAX`): no job is cut by a
/// synchronization point before it holds this many bytes.
const rsync_min_block_log = 17;
const rsync_min_block_size: usize = 1 << rsync_min_block_log;
/// `prime8bytes`, the rolling hash's multiplier.
const prime8bytes: u64 = 0xCF1BBCDCB7A56463;
/// `ZSTD_ROLL_HASH_CHAR_OFFSET`.
const roll_hash_char_offset = 10;

/// `ZSTD_rollingHash_append`: `buf` added to `hash`.
fn rollingHashAppend(hash_in: u64, buf: []const u8) u64 {
    var hash = hash_in;
    for (buf) |b| hash = hash *% prime8bytes +% (@as(u64, b) + roll_hash_char_offset);
    return hash;
}

/// `ZSTD_rollingHash_compute`.
fn rollingHashCompute(buf: []const u8) u64 {
    return rollingHashAppend(0, buf);
}

/// `ZSTD_rollingHash_primePower`: `prime8bytes` to the `length - 1`.
fn rollingHashPrimePower(length: u32) u64 {
    var power: u64 = 1;
    for (1..length) |_| power *%= prime8bytes;
    return power;
}

/// `ZSTD_rollingHash_rotate`: the window moves by one byte.
fn rollingHashRotate(hash: u64, to_remove: u8, to_add: u8, prime_power: u64) u64 {
    return (hash -% (@as(u64, to_remove) + roll_hash_char_offset) *% prime_power) *% prime8bytes +% (@as(u64, to_add) + roll_hash_char_offset);
}

pub const JobError = frame.BeginError || frame.Compressor.SizeError || frame.BlockError; // (no producer reaches a job: refused with workers)

pub const Error = JobError || error{
    /// `ZSTD_e_continue` after `ZSTD_e_end` asked to end a frame that is
    /// not complete yet (`stage_wrong`).
    StageWrong,
};

/// Large buffers (the round buffer, the jobs' outputs: hundreds of MB at
/// the highest levels) straight from the allocator's vtable: `alloc` would
/// fill them with `undefined` in a safe build, making every page resident
/// although a frame may use a fraction of it (libzstd's `malloc` does not
/// touch them either).
const RawBuf = struct {
    fn alloc(gpa: std.mem.Allocator, n: usize) error{OutOfMemory}![]align(64) u8 {
        if (n == 0) return &.{};
        const p = gpa.rawAlloc(n, .@"64", @returnAddress()) orelse return error.OutOfMemory;
        return @alignCast(p[0..n]);
    }
    fn free(gpa: std.mem.Allocator, b: []align(64) u8) void {
        if (b.len != 0) gpa.rawFree(b, .@"64", @returnAddress());
    }
};

/// The futex, from the process-global `std.Io.Threaded`: its futex calls
/// use no state of the instance (Linux futex, or the parking futex).
const Futex = struct {
    fn io() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }
    fn wait(word: *const std.atomic.Value(u32), expected: u32) void {
        io().futexWaitUncancelable(u32, &word.raw, expected);
    }
    fn wake(word: *const std.atomic.Value(u32), n: u32) void {
        io().futexWake(u32, &word.raw, n);
    }
};

/// `ZSTDMT_jobDescription`. The main thread sets the first group and posts
/// the job; the worker publishes its progress through `c_size` and
/// `consumed` (a job is complete when `consumed == src.len`), bumping
/// `progress` (the futex word) each time.
const Job = struct {
    src: []const u8 = &.{},
    prefix: []const u8 = &.{},
    id: u32 = 0,
    first: bool = false,
    last: bool = false,
    cdict: ?*const CDict = null,
    full_frame_size: ?u64 = null,
    cp: params.CParams = undefined,
    opts: frame.Options = undefined,
    /// The serially made long-distance matches for `src`.
    seqs: ldm.RawSeqStore = .{},
    /// Owned buffers, kept from job to job in this slot.
    seq_buf: []ldm.RawSeq = &.{},
    dst_buf: []align(64) u8 = &.{},
    /// `dstBuff`: `compressBound(targetSectionSize)` bytes of `dst_buf`,
    /// which has 4 more for the checksum.
    dst: []u8 = &.{},

    c_size: std.atomic.Value(usize) = .init(0),
    consumed: std.atomic.Value(usize) = .init(0),
    progress: std.atomic.Value(u32) = .init(0),
    /// Set before `consumed` reaches `src.len`.
    err: ?JobError = null,

    // main thread only
    dst_flushed: usize = 0,
    frame_checksum_needed: bool = false,

    /// Worker side: publish a chunk's output and progress.
    fn publish(job: *Job, c_add: usize, consumed: usize) void {
        _ = job.c_size.fetchAdd(c_add, .release);
        job.consumed.store(consumed, .release);
        _ = job.progress.fetchAdd(1, .release);
        Futex.wake(&job.progress, 1);
    }

    /// `ZSTDMT_compressionJob`, on `cctx`. `finished` counts the pool's
    /// completed jobs (bumped before the job is published complete).
    fn run(job: *Job, cctx: *frame.Compressor, finished: ?*std.atomic.Value(u32)) void {
        var last_c: usize = 0;
        job.compress(cctx, &last_c) catch |e| {
            job.err = e;
            last_c = 0;
        };
        if (finished) |f| _ = f.fetchAdd(1, .release);
        // when consumed == src.len, the compression job is presumed completed
        job.publish(last_c, job.src.len);
    }

    fn compress(job: *Job, cctx: *frame.Compressor, last_c: *usize) JobError!void {
        var o = job.opts;
        // Don't compute the checksum for chunks, since we compute it
        // externally, but write it in the header.
        if (job.id != 0) o.checksum = false;
        // Don't run LDM for the chunks, since we handle it externally
        o.advanced.long_distance_matching = .disable;
        o.dict = .none;
        if (job.cdict) |cd| {
            std.debug.assert(job.first); // only allowed for first job
            try cctx.beginInternal(null, cd, job.cp, job.full_frame_size, o, false);
        } else {
            const pledged: ?u64 = if (job.first) job.full_frame_size else job.src.len;
            o.advanced.force_max_window = !job.first;
            if (!job.first) o.advanced.deterministic_ref_prefix = false;
            try cctx.beginInternal(.{ .bytes = job.prefix, .content_type = .raw_content }, null, job.cp, pledged, o, false);
        }
        // External Sequences can only be applied after CCtx initialization
        if (job.seqs.size > 0) cctx.c.extern_seqs = job.seqs;

        const dst = job.dst;
        if (!job.first) { // flush and overwrite frame header when it's not first job
            _ = try cctx.compressContinue(dst, job.src[0..0], false);
            cctx.c.prev.rep = .{ 0, 0, 0 }; // ZSTD_invalidateRepCodes
        }

        // compress the entire job by smaller chunks, for better granularity
        const src = job.src;
        const nb_chunks = (src.len + chunk_size - 1) / chunk_size;
        var ip: usize = 0;
        var op: usize = 0;
        var chunk_nb: usize = 1;
        while (chunk_nb < nb_chunks) : (chunk_nb += 1) {
            const c_size = try cctx.compressContinue(dst[op..], src[ip..][0..chunk_size], false);
            ip += chunk_size;
            op += c_size;
            job.publish(c_size, chunk_size * chunk_nb);
        }
        // last block
        if (nb_chunks > 0 or job.last) { // must output a "last block" flag
            const last_block_size1 = src.len & (chunk_size - 1);
            const last_block_size = if (last_block_size1 == 0 and src.len >= chunk_size) chunk_size else last_block_size1;
            const chunk = src[ip..][0..last_block_size];
            last_c.* = if (job.last) blk: {
                // ZSTD_compressEnd_public
                const n = try cctx.compressContinue(dst[op..], chunk, true);
                const m = try cctx.writeEpilogue(dst[op + n ..]);
                if (cctx.pledged) |p| if (p != cctx.consumed) return error.SrcSizeWrong;
                break :blk n + m;
            } else try cctx.compressContinue(dst[op..], chunk, false);
        }
    }
};

/// A fixed set of worker threads, each with its own compression context,
/// taking posted jobs in order. At most one job per thread is in flight:
/// `tryAdd` refuses a job when every thread is busy (`POOL_tryAdd` on a
/// pool with no queue), and the caller keeps it ready (`jobReady`).
const Pool = struct {
    threads: []std.Thread = &.{},
    queue: []*Job = &.{},
    // `unsigned` (32-bit) in libzstd's own `nextJobID`/`doneJobID`
    // (`zstdmt_compress.c`) -- not just matching that width but required by
    // it: a 32-bit target (`check-portable`'s `.linux32`) has no native
    // 64-bit atomic ops, and `std.atomic.Value(u64)` fails to compile there
    // (`std/atomic.zig`'s `@atomicLoad`/`Store`/`Rmw` need <= register
    // width). A `u32` sequence wrapping around would need over 4 billion
    // jobs in one compression -- unreachable at any realistic job size.
    posted: std.atomic.Value(u32) = .init(0),
    taken: std.atomic.Value(u32) = .init(0),
    finished: std.atomic.Value(u32) = .init(0),
    /// The futex word idle workers sleep on.
    wake_seq: std.atomic.Value(u32) = .init(0),
    shutdown: std.atomic.Value(bool) = .init(false),
    cctxs: []frame.Compressor = &.{},

    /// `queue.len` is the worker count -- a handful, always representable
    /// in `u32` -- so a sequence number's slot is a `u32 % u32` (matching
    /// `posted`/`taken`/`finished`'s own width), cast to `usize` only at
    /// the very end, for the index.
    fn slot(pool: *Pool, seq_no: u32) usize {
        return seq_no % @as(u32, @intCast(pool.queue.len));
    }

    fn worker(pool: *Pool, idx: usize) void {
        while (true) {
            const seq = pool.wake_seq.load(.acquire);
            if (pool.shutdown.load(.acquire)) return;
            const t = pool.taken.load(.acquire);
            if (t < pool.posted.load(.acquire)) {
                if (pool.taken.cmpxchgWeak(t, t + 1, .acq_rel, .monotonic) == null)
                    pool.queue[pool.slot(t)].run(&pool.cctxs[idx], &pool.finished);
                continue;
            }
            Futex.wait(&pool.wake_seq, seq);
        }
    }

    fn tryAdd(pool: *Pool, job: *Job) bool {
        const p = pool.posted.load(.monotonic);
        if (p - pool.finished.load(.acquire) >= @as(u32, @intCast(pool.threads.len))) return false;
        pool.queue[pool.slot(p)] = job;
        pool.posted.store(p + 1, .release);
        _ = pool.wake_seq.fetchAdd(1, .release);
        Futex.wake(&pool.wake_seq, 1);
        return true;
    }

    fn start(pool: *Pool, gpa: std.mem.Allocator, n: usize) error{OutOfMemory}!void {
        std.debug.assert(pool.threads.len == 0);
        const queue = try gpa.alloc(*Job, n);
        const threads = gpa.alloc(std.Thread, n) catch |e| {
            gpa.free(queue);
            return e;
        };
        pool.queue = queue;
        pool.shutdown.store(false, .release);
        pool.posted.store(0, .monotonic);
        pool.taken.store(0, .monotonic);
        pool.finished.store(0, .monotonic);
        for (threads, 0..) |*t, i| {
            t.* = std.Thread.spawn(.{}, worker, .{ pool, i }) catch {
                pool.threads = threads[0..i];
                pool.stop(gpa);
                gpa.free(threads);
                return error.OutOfMemory;
            };
        }
        pool.threads = threads;
    }

    /// Joins the threads (idle ones: the caller waited for every job).
    fn stop(pool: *Pool, gpa: std.mem.Allocator) void {
        pool.shutdown.store(true, .release);
        _ = pool.wake_seq.fetchAdd(1, .release);
        Futex.wake(&pool.wake_seq, std.math.maxInt(u32));
        for (pool.threads) |t| t.join();
        if (pool.threads.len == pool.queue.len) gpa.free(pool.threads);
        gpa.free(pool.queue);
        pool.threads = &.{};
        pool.queue = &.{};
    }
};

/// `ZSTDMT_CCtx`: a multithreaded compression context, reused frame after
/// frame (`initFrame`, then `compressStream2` until the frame ends).
/// Heap-allocated (its threads point at it): `create`, `destroy`.
pub const MtCtx = struct {
    gpa: std.mem.Allocator,
    n_workers: u32 = 0,
    /// Test seam: run each job on the calling thread when it is posted,
    /// with no threads at all. The bytes are the same.
    run_inline: bool = false,
    pool: Pool = .{},

    jobs: []Job = &.{},
    job_mask: u32 = 0,

    cp: params.CParams = undefined,
    opts: frame.Options = undefined,
    /// `params.fParams.checksumFlag`: cleared when the frame is one job
    /// (which writes the checksum itself).
    checksum: bool = false,
    target_section_size: usize = 0,
    target_prefix_size: usize = 0,
    job_ready: bool = false,
    /// `rsync` (`RSyncState_t`), with `rsyncable` only.
    rsync: ?Rsync = null,

    /// `roundBuff`: `round` lies one cache line into `round_alloc`, so no
    /// caller's buffer can end where it starts (a window would take the
    /// two as contiguous).
    round_alloc: []align(64) u8 = &.{},
    round: []u8 = &.{},
    round_pos: usize = 0,
    /// `inBuff`: the prefix the next job reloads, and the part of `round`
    /// being filled.
    in_prefix: []const u8 = &.{},
    in_buffer: ?[]u8 = null,
    in_filled: usize = 0,

    done_job_id: u32 = 0,
    next_job_id: u32 = 0,
    frame_ended: bool = false,
    all_jobs_completed: bool = true,
    frame_content_size: ?u64 = null,
    /// Input taken into jobs or the buffer this frame (not libzstd's: it
    /// checks the pledged size, which libzstd's jobs check only partly).
    ingested: u64 = 0,
    consumed: u64 = 0,
    produced: u64 = 0,

    cdict: ?*const CDict = null,
    cdict_local: ?CDict = null,

    // SerialState
    serial_ldm: ?ldm.State = null,
    ldm_table: []ldm.Entry = &.{},
    ldm_buckets: []u8 = &.{},
    seq_capacity: usize = 0,
    xxh: std.hash.XxHash64 = .init(0),
    serial_checksum: bool = false,

    /// `ZSTDMT_createCCtx_advanced`: a context for `n_workers` threads
    /// (at least 1). With `run_inline`, no thread is started.
    pub fn create(gpa: std.mem.Allocator, n_workers: u32, run_inline: bool) error{OutOfMemory}!*MtCtx {
        std.debug.assert(n_workers >= 1);
        const mt = try gpa.create(MtCtx);
        errdefer gpa.destroy(mt);
        mt.* = .{ .gpa = gpa, .run_inline = run_inline or builtin.single_threaded };
        errdefer mt.freeAll();
        try mt.resize(n_workers);
        return mt;
    }

    pub fn destroy(mt: *MtCtx) void {
        const gpa = mt.gpa;
        if (!mt.all_jobs_completed) mt.waitForAllJobsCompleted();
        mt.freeAll();
        gpa.destroy(mt);
    }

    fn freeAll(mt: *MtCtx) void {
        const gpa = mt.gpa;
        if (mt.pool.threads.len != 0) mt.pool.stop(gpa);
        for (mt.pool.cctxs) |*c| c.deinit();
        gpa.free(mt.pool.cctxs);
        mt.pool.cctxs = &.{};
        mt.freeJobs();
        RawBuf.free(gpa, mt.round_alloc);
        mt.round_alloc = &.{};
        gpa.free(mt.ldm_table);
        gpa.free(mt.ldm_buckets);
        mt.ldm_table = &.{};
        mt.ldm_buckets = &.{};
        if (mt.cdict_local) |*l| l.deinit();
        mt.cdict_local = null;
    }

    fn freeJobs(mt: *MtCtx) void {
        for (mt.jobs) |*j| {
            mt.gpa.free(j.seq_buf);
            RawBuf.free(mt.gpa, j.dst_buf);
        }
        mt.gpa.free(mt.jobs);
        mt.jobs = &.{};
    }

    /// The workers' contexts' workspaces and every buffer held
    /// (`ZSTDMT_sizeof_CCtx` less the structures).
    pub fn memorySize(mt: *const MtCtx) usize {
        var n: usize = mt.round_alloc.len + mt.ldm_table.len * @sizeOf(ldm.Entry) + mt.ldm_buckets.len;
        for (mt.pool.cctxs) |c| n += c.ws.len;
        for (mt.jobs) |j| n += j.dst_buf.len + j.seq_buf.len * @sizeOf(ldm.RawSeq);
        if (mt.cdict_local) |*l| n += l.memorySize();
        return n;
    }

    /// `ZSTDMT_resize` / `ZSTDMT_expandJobsTable` / the CCtx pool: `n`
    /// threads, each with a context, and a job table of a power of two
    /// above `n + 2`. Only between frames.
    fn resize(mt: *MtCtx, n: u32) error{OutOfMemory}!void {
        const gpa = mt.gpa;
        if (mt.pool.threads.len != 0) mt.pool.stop(gpa);
        const n_ctx: usize = if (mt.run_inline) 1 else n;
        if (mt.pool.cctxs.len != n_ctx) {
            const old = mt.pool.cctxs;
            const cctxs = try gpa.alloc(frame.Compressor, n_ctx);
            for (cctxs, 0..) |*c, i| c.* = if (i < old.len) old[i] else .initEmpty(gpa);
            if (old.len > n_ctx) for (old[n_ctx..]) |*c| c.deinit();
            gpa.free(old);
            mt.pool.cctxs = cctxs;
        }
        // ZSTDMT_createJobsTable: 2^(highbit32(nbJobs) + 1) slots
        const nb_jobs: u32 = n + 2;
        const table_len = @as(usize, 1) << @intCast(std.math.log2_int(u32, nb_jobs) + 1);
        if (nb_jobs > mt.jobs.len) {
            mt.freeJobs();
            mt.jobs = try gpa.alloc(Job, table_len);
            for (mt.jobs) |*j| j.* = .{};
            mt.job_mask = @intCast(table_len - 1);
        }
        if (!mt.run_inline) try mt.pool.start(gpa, n);
        mt.n_workers = n;
    }

    /// `ZSTDMT_initCStream_internal`: set up a frame from what
    /// `ZSTD_CCtx_init_compressStream2` settled (`setup`), of `pledged`
    /// bytes (null: unknown).
    pub fn initFrame(mt: *MtCtx, setup: frame.Compressor.StreamSetup, pledged: ?u64) CDict.InitError!void {
        const gpa = mt.gpa;
        const adv = setup.opts.advanced;
        std.debug.assert(adv.nb_workers >= 1);
        if (!mt.all_jobs_completed) { // previous compression not correctly finished
            mt.waitForAllJobsCompleted();
            mt.releaseAllJobResources();
        }
        if (adv.nb_workers != mt.n_workers) try mt.resize(adv.nb_workers);

        var job_size: usize = adv.job_size;
        if (job_size != 0 and job_size < job_size_min) job_size = job_size_min;
        if (job_size > job_size_max) job_size = job_size_max;

        const cp = setup.cp;
        const ldm_on = ldm.resolve(adv.long_distance_matching, cp);
        mt.cp = cp;
        mt.opts = setup.opts;
        mt.frame_content_size = pledged;

        mt.target_prefix_size = computeOverlapSize(cp, adv.overlap_log, ldm_on);
        mt.target_section_size = job_size;
        if (mt.target_section_size == 0) mt.target_section_size = @as(usize, 1) << @intCast(computeTargetJobLog(cp, ldm_on));
        mt.rsync = null;
        if (adv.rsyncable) {
            // Aim for the targetsectionSize as the average job size.
            const job_size_kb: u32 = @intCast(mt.target_section_size >> 10);
            const rsync_bits: u6 = @intCast(std.math.log2_int(u32, job_size_kb) + 10);
            // We refuse to create jobs < RSYNC_MIN_BLOCK_SIZE bytes, so make
            // sure our expected job size is at least 4x larger.
            std.debug.assert(rsync_bits >= rsync_min_block_log + 2);
            mt.rsync = .{ .hit_mask = (@as(u64, 1) << rsync_bits) - 1, .prime_power = rollingHashPrimePower(rsync_length) };
        }
        // job size must be >= overlap size
        if (mt.target_section_size < mt.target_prefix_size) mt.target_section_size = mt.target_prefix_size;
        {
            // If ldm is enabled we need windowSize space.
            const window_size: usize = if (ldm_on) @as(usize, 1) << @intCast(cp.window_log) else 0;
            // Two buffers of slack, plus extra space for the overlap. This
            // is the minimum slack that LDM works with. One extra because
            // flush might waste up to targetSectionSize-1 bytes. Another
            // extra for the overlap (if > 0), then one to fill which doesn't
            // overlap with the LDM window.
            const nb_slack_buffers: usize = @as(usize, 2) + @intFromBool(mt.target_prefix_size > 0);
            const slack_size = mt.target_section_size * nb_slack_buffers;
            // Compute the total size, and always have enough slack
            const sections_size = mt.target_section_size * @max(mt.n_workers, 1);
            const capacity = @max(window_size, sections_size) + slack_size;
            if (mt.round.len < capacity) {
                RawBuf.free(gpa, mt.round_alloc);
                mt.round_alloc = &.{};
                mt.round = &.{};
                mt.round_alloc = try RawBuf.alloc(gpa, capacity + 64);
            }
            mt.round = mt.round_alloc[64..][0..capacity];
        }
        mt.round_pos = 0;
        mt.in_buffer = null;
        mt.in_filled = 0;
        mt.in_prefix = &.{};
        mt.done_job_id = 0;
        mt.next_job_id = 0;
        mt.frame_ended = false;
        mt.all_jobs_completed = false;
        mt.job_ready = false;
        mt.consumed = 0;
        mt.produced = 0;
        mt.ingested = 0;
        mt.checksum = setup.opts.checksum;

        // update dictionary
        if (mt.cdict_local) |*l| l.deinit();
        mt.cdict_local = null;
        mt.cdict = null;
        var raw_prefix: []const u8 = &.{};
        if (setup.prefix) |p| {
            if (p.content_type == .raw_content) {
                mt.in_prefix = p.bytes;
                raw_prefix = p.bytes;
            } else {
                // a loadPrefix becomes an internal CDict (by reference,
                // with the frame's parameters and no level)
                mt.cdict_local = try CDict.initReference(gpa, p.bytes, .{ .level = 0, .content_type = p.content_type, .advanced = asAdvanced(cp) });
                mt.cdict = &mt.cdict_local.?;
            }
        } else mt.cdict = setup.cdict;

        try mt.serialReset(ldm_on, raw_prefix);
    }

    /// The parameters `cp` set explicitly (`ZSTD_createCDict_advanced`).
    fn asAdvanced(cp: params.CParams) params.Advanced {
        return .{
            .window_log = cp.window_log,
            .hash_log = cp.hash_log,
            .chain_log = cp.chain_log,
            .search_log = cp.search_log,
            .min_match = cp.min_match,
            .target_length = cp.target_length,
            .strategy = cp.strategy,
        };
    }

    /// `ZSTDMT_serialState_reset`: the LDM table and window from scratch
    /// (a raw-content prefix loaded into them), the checksum.
    fn serialReset(mt: *MtCtx, ldm_on: bool, raw_prefix: []const u8) error{OutOfMemory}!void {
        const gpa = mt.gpa;
        mt.serial_checksum = mt.opts.checksum;
        mt.xxh = .init(0);
        mt.serial_ldm = null;
        mt.seq_capacity = 0;
        if (!ldm_on) return;
        const lp = ldm.adjustParameters(mt.cp, mt.opts.advanced);
        const hash_size = @as(usize, 1) << @intCast(lp.hash_log);
        const num_buckets = @as(usize, 1) << @intCast(lp.hash_log - lp.bucket_size_log);
        // Size the seq pool tables
        mt.seq_capacity = ldm.maxNbSeq(lp, mt.target_section_size);
        // Resize tables and output space if necessary.
        if (mt.ldm_table.len < hash_size) {
            gpa.free(mt.ldm_table);
            mt.ldm_table = &.{};
            mt.ldm_table = try gpa.alloc(ldm.Entry, hash_size);
        }
        if (mt.ldm_buckets.len < num_buckets) {
            gpa.free(mt.ldm_buckets);
            mt.ldm_buckets = &.{};
            mt.ldm_buckets = try gpa.alloc(u8, num_buckets);
        }
        // Zero the tables
        @memset(mt.ldm_table[0..hash_size], .{});
        @memset(mt.ldm_buckets[0..num_buckets], 0);
        mt.serial_ldm = .{
            .p = lp,
            .hash_table = mt.ldm_table[0..hash_size],
            .bucket_offsets = mt.ldm_buckets[0..num_buckets],
            .buffer = mt.round,
            .overflow_correct_frequently = mt.opts.overflow_correct_frequently,
        };
        // Update window state and fill hash table with dict
        if (raw_prefix.len > 0) {
            const ls = &mt.serial_ldm.?;
            ls.windowUpdate(raw_prefix);
            ls.fillHashTable(raw_prefix);
            ls.loaded_dict_end = if (mt.opts.advanced.force_max_window) 0 else @intCast(ls.src_base + ls.src.len);
        }
    }

    /// `ZSTDMT_waitForAllJobsCompleted`.
    fn waitForAllJobsCompleted(mt: *MtCtx) void {
        while (mt.done_job_id < mt.next_job_id) : (mt.done_job_id += 1) {
            const job = &mt.jobs[mt.done_job_id & mt.job_mask];
            while (true) {
                const seq = job.progress.load(.acquire);
                if (job.consumed.load(.acquire) >= job.src.len) break;
                Futex.wait(&job.progress, seq);
            }
        }
    }

    /// `ZSTDMT_releaseAllJobResources` (the slots keep their buffers).
    fn releaseAllJobResources(mt: *MtCtx) void {
        for (mt.jobs) |*j| {
            const seq_buf = j.seq_buf;
            const dst_buf = j.dst_buf;
            j.* = .{ .seq_buf = seq_buf, .dst_buf = dst_buf };
        }
        mt.in_buffer = null;
        mt.in_filled = 0;
        mt.all_jobs_completed = true;
    }

    /// Abandon the current frame, if any (`ZSTD_CCtx_reset` mid-frame).
    pub fn abandon(mt: *MtCtx) void {
        if (mt.all_jobs_completed) return;
        mt.waitForAllJobsCompleted();
        mt.releaseAllJobResources();
    }

    /// The `nbWorkers > 0` branch of `ZSTD_compressStream2`: some progress
    /// for `continue`, as much as the output allows for `flush` and `end`.
    /// Returns what is left to flush (0 with `end`: the frame is complete;
    /// the caller then resets the session).
    pub fn compressStream2(mt: *MtCtx, output: *stream.OutBuffer, input: *stream.InBuffer, end_op: stream.EndDirective) Error!usize {
        while (true) {
            const ipos = input.pos;
            const opos = output.pos;
            const flush_min = try mt.generic(output, input, end_op);
            if (end_op == .@"continue") {
                // We only require some progress with ZSTD_e_continue, not
                // maximal progress. We're done if we've consumed or produced
                // any bytes, or either buffer is full.
                if (input.pos != ipos or output.pos != opos or input.pos == input.src.len or output.pos == output.dst.len)
                    return flush_min;
            } else {
                // We require maximal progress. We're done when the flush is
                // complete or the output buffer is full.
                if (flush_min == 0 or output.pos == output.dst.len) return flush_min;
            }
        }
    }

    /// `ZSTDMT_compressStream_generic`.
    fn generic(mt: *MtCtx, output: *stream.OutBuffer, input: *stream.InBuffer, end_op_in: stream.EndDirective) Error!usize {
        var end_op = end_op_in;
        var forward_input_progress = false;
        // current frame being ended. Only flush/end are allowed
        if (mt.frame_ended and end_op == .@"continue") return error.StageWrong;

        // fill input buffer
        if (!mt.job_ready and input.src.len > input.pos) {
            if (mt.in_buffer == null) {
                // It is only possible for this operation to fail if there
                // are still compression jobs ongoing.
                if (!mt.tryGetInputRange()) std.debug.assert(mt.done_job_id != mt.next_job_id);
            }
            if (mt.in_buffer) |buf| {
                const sync = mt.findSynchronizationPoint(input.*);
                if (sync.flush and end_op == .@"continue") end_op = .flush;
                const to_load = sync.to_load;
                if (mt.frame_content_size) |p| if (mt.ingested + to_load > p) return error.SrcSizeWrong;
                @memcpy(buf[mt.in_filled..][0..to_load], input.src[input.pos..][0..to_load]);
                input.pos += to_load;
                mt.in_filled += to_load;
                mt.ingested += to_load;
                forward_input_progress = to_load > 0;
            }
        }
        if (input.pos < input.src.len and end_op == .end) {
            // Can't end yet because the input is not fully consumed: we
            // couldn't get an input buffer, or we filled it.
            end_op = .flush;
        }

        if (mt.job_ready or // one job is prepared but was not posted
            mt.in_filled >= mt.target_section_size or // filled enough : let's compress
            (end_op != .@"continue" and mt.in_filled > 0) or // something to flush : let's go
            (end_op == .end and !mt.frame_ended)) // must finish the frame with a zero-size block
        {
            try mt.createCompressionJob(mt.in_filled, end_op);
        }

        // check for potential compressed data ready to be flushed; block if
        // there was no forward input progress
        const remaining = try mt.flushProduced(output, !forward_input_progress, end_op);
        if (input.pos < input.src.len) return @max(remaining, 1); // input not consumed : do not end flush yet
        return remaining;
    }

    const Rsync = struct { hit_mask: u64, prime_power: u64 };
    const SyncPoint = struct { to_load: usize, flush: bool = false };

    /// `findSynchronizationPoint`: how much of `input` to load -- as much
    /// as fits the job, or, with `rsyncable`, up to and including the first
    /// byte (at least `rsync_min_block_size` into the job) at which the
    /// rolling hash of the last 32 bytes hits the mask, which then ends the
    /// job (`flush`).
    fn findSynchronizationPoint(mt: *const MtCtx, input: stream.InBuffer) SyncPoint {
        const istart = input.src[input.pos..];
        var sync: SyncPoint = .{ .to_load = @min(istart.len, mt.target_section_size - mt.in_filled) };
        const rs = mt.rsync orelse return sync; // Rsync is disabled.
        const filled = mt.in_filled;
        // We don't emit synchronization points if it would produce too
        // small blocks. We don't have enough input to find a
        // synchronization point, so don't look.
        if (filled + istart.len < rsync_min_block_size) return sync;
        // Not enough to compute the hash. We will miss any synchronization
        // points in this RSYNC_LENGTH byte window. However, since it depends
        // only in the internal buffers, if the state is already
        // synchronized, we will remain synchronized.
        if (filled + sync.to_load < rsync_length) return sync;
        const buf = mt.in_buffer.?;
        var hash: u64 = undefined;
        var prev: []const u8 = undefined;
        var pos: usize = undefined;
        // Initialize the loop variables.
        if (filled < rsync_min_block_size) {
            // We don't need to scan the first RSYNC_MIN_BLOCK_SIZE positions
            // because they can't possibly be a sync point. So we can start
            // part way through the input buffer.
            pos = rsync_min_block_size - filled;
            if (pos >= rsync_length) {
                prev = istart[pos - rsync_length ..];
                hash = rollingHashCompute(prev[0..rsync_length]);
            } else {
                std.debug.assert(filled >= rsync_length);
                prev = buf[filled - rsync_length ..];
                hash = rollingHashCompute(prev[pos..rsync_length]);
                hash = rollingHashAppend(hash, istart[0..pos]);
            }
        } else {
            // We have enough bytes buffered to initialize the hash, and have
            // processed enough bytes to find a sync point. Start scanning at
            // the beginning of the input.
            pos = 0;
            prev = buf[filled - rsync_length ..];
            hash = rollingHashCompute(prev[0..rsync_length]);
            if (hash & rs.hit_mask == rs.hit_mask) {
                // We're already at a sync point so don't load any more until
                // we're able to flush this sync point. This likely happened
                // because the job table was full so we couldn't add our job.
                return .{ .to_load = 0, .flush = true };
            }
        }
        // Starting with the hash of the previous RSYNC_LENGTH bytes, roll
        // through the input. If we hit a synchronization point, then cut the
        // job off, and tell the compressor to flush the job. Otherwise, load
        // all the bytes and continue as normal. If we go too long without a
        // synchronization point (targetSectionSize) then a block will be
        // emitted anyways, but this is okay, since if we are already
        // synchronized we will remain synchronized.
        while (pos < sync.to_load) : (pos += 1) {
            const to_remove = if (pos < rsync_length) prev[pos] else istart[pos - rsync_length];
            hash = rollingHashRotate(hash, to_remove, istart[pos], rs.prime_power);
            std.debug.assert(filled + pos >= rsync_min_block_size);
            if (hash & rs.hit_mask == rs.hit_mask) {
                sync.to_load = pos + 1;
                sync.flush = true;
                break;
            }
        }
        return sync;
    }

    const Range = struct {
        ptr: usize = 0,
        len: usize = 0,

        fn of(s: []const u8) Range {
            return .{ .ptr = @intFromPtr(s.ptr), .len = s.len };
        }

        /// `ZSTDMT_isOverlapped`: empty ranges cannot overlap.
        fn overlaps(a: Range, b: Range) bool {
            if (a.ptr == 0 or b.ptr == 0 or a.len == 0 or b.len == 0) return false;
            return a.ptr < b.ptr + b.len and b.ptr < a.ptr + a.len;
        }
    };

    /// `ZSTDMT_getInputDataInUse`: the prefix (or, without one, the input)
    /// of the earliest job not complete.
    fn getInputDataInUse(mt: *MtCtx) Range {
        // no need to check during first round
        const nb_jobs_1st_round_min = mt.round.len / mt.target_section_size;
        if (mt.next_job_id < nb_jobs_1st_round_min) return .{};
        var id = mt.done_job_id;
        while (id < mt.next_job_id) : (id += 1) {
            const job = &mt.jobs[id & mt.job_mask];
            if (job.consumed.load(.acquire) < job.src.len) {
                // (job source in multiple segments not supported yet)
                return if (job.prefix.len == 0) .of(job.src) else .of(job.prefix);
            }
        }
        return .{};
    }

    /// `ZSTDMT_tryGetInputRange`: the next section of the round buffer to
    /// fill, unless part of it is still in use. At the end of the buffer,
    /// the prefix moves to its start (the next job's window must be one
    /// segment).
    fn tryGetInputRange(mt: *MtCtx) bool {
        const in_use = mt.getInputDataInUse();
        const space_left = mt.round.len - mt.round_pos;
        const space_needed = mt.target_section_size;
        std.debug.assert(mt.in_buffer == null);
        std.debug.assert(mt.round.len >= space_needed);
        if (space_left < space_needed) {
            // ZSTD_invalidateRepCodes() doesn't work for extDict variants.
            // Simply copy the prefix to the beginning in that case.
            const prefix_size = mt.in_prefix.len;
            const start = mt.round[0..prefix_size];
            if (Range.of(start).overlaps(in_use)) return false; // waiting for buffer
            mt.checkLdmWindow(start);
            std.mem.copyForwards(u8, start, mt.in_prefix);
            mt.in_prefix = start;
            mt.round_pos = prefix_size;
        }
        const buffer = mt.round[mt.round_pos..][0..space_needed];
        if (Range.of(buffer).overlaps(in_use)) return false; // waiting for buffer
        std.debug.assert(!Range.of(buffer).overlaps(.of(mt.in_prefix)));
        mt.checkLdmWindow(buffer);
        mt.in_buffer = buffer;
        mt.in_filled = 0;
        return true;
    }

    /// `ZSTDMT_waitForLdmComplete`: libzstd waits until the serial LDM
    /// window no longer covers `buffer`. Here the serial step of every job
    /// made so far has run, and no later one can move the window, so it
    /// never does cover it (else libzstd would wait forever).
    fn checkLdmWindow(mt: *const MtCtx, buffer: []const u8) void {
        if (!std.debug.runtime_safety) return;
        const ls = &(mt.serial_ldm orelse return);
        const b: i128 = @intFromPtr(buffer.ptr);
        const e: i128 = b + buffer.len;
        const dict_origin: i128 = @as(i128, @intFromPtr(ls.dict.ptr)) - ls.dict_base;
        const src_origin: i128 = @as(i128, @intFromPtr(ls.src.ptr)) - ls.src_base;
        const segs = [2][2]i128{
            .{ dict_origin + ls.low_limit, dict_origin + ls.dict_limit },
            .{ src_origin + ls.dict_limit, src_origin + ls.src_base + ls.src.len },
        };
        for (segs) |seg| if (seg[0] < seg[1]) std.debug.assert(!(b < seg[1] and seg[0] < e));
    }

    /// `ZSTDMT_createCompressionJob`: the buffered input as the next job
    /// (the last one with `end`), posted to a worker if one is free.
    fn createCompressionJob(mt: *MtCtx, src_size: usize, end_op: stream.EndDirective) Error!void {
        const job = &mt.jobs[mt.next_job_id & mt.job_mask];
        const end_frame = end_op == .end;
        if (mt.next_job_id > mt.done_job_id + mt.job_mask) {
            // will not create new job : table is full
            std.debug.assert((mt.next_job_id & mt.job_mask) == (mt.done_job_id & mt.job_mask));
            return;
        }

        if (!mt.job_ready) {
            if (end_frame) if (mt.frame_content_size) |p| if (mt.ingested != p) return error.SrcSizeWrong;
            const src: []const u8 = if (mt.in_buffer) |b| b[0..src_size] else &.{};
            std.debug.assert(mt.in_filled >= src_size);
            try mt.slotBuffers(job);
            job.src = src;
            job.prefix = mt.in_prefix;
            job.consumed.store(0, .monotonic);
            job.c_size.store(0, .monotonic);
            job.err = null;
            job.cp = mt.cp;
            job.opts = mt.opts;
            job.opts.checksum = mt.checksum;
            job.cdict = if (mt.next_job_id == 0) mt.cdict else null;
            job.full_frame_size = mt.frame_content_size;
            job.id = mt.next_job_id;
            job.first = mt.next_job_id == 0;
            job.last = end_frame;
            job.frame_checksum_needed = mt.checksum and end_frame and mt.next_job_id > 0;
            job.dst_flushed = 0;

            // Update the round buffer pos and clear the input buffer to be reset
            mt.round_pos += src_size;
            mt.in_buffer = null;
            mt.in_filled = 0;
            // Set the prefix for next job
            if (!end_frame) {
                const new_prefix_size = @min(src_size, mt.target_prefix_size);
                mt.in_prefix = src[src_size - new_prefix_size ..];
            } else { // endFrame==1 => no need for another input buffer
                mt.in_prefix = &.{};
                mt.frame_ended = true;
                // single job exception : checksum is already calculated
                // directly within worker thread
                if (mt.next_job_id == 0) mt.checksum = false;
            }

            if (src_size == 0 and mt.next_job_id > 0) { // single job must also write frame header
                // creating a last empty block to end frame
                std.debug.assert(end_op == .end);
                mt.writeLastEmptyBlock(job);
                mt.next_job_id += 1;
                return;
            }
            mt.serialStep(job);
        }

        if (mt.post(job)) {
            mt.next_job_id += 1;
            mt.job_ready = false;
        } else {
            // no worker available for the job
            mt.job_ready = true;
        }
    }

    /// The slot's output and sequence buffers, (re)sized for this frame.
    fn slotBuffers(mt: *MtCtx, job: *Job) error{OutOfMemory}!void {
        const bound = frame.compressBound(mt.target_section_size);
        if (job.dst_buf.len < bound + 4) {
            RawBuf.free(mt.gpa, job.dst_buf);
            job.dst_buf = &.{};
            job.dst_buf = try RawBuf.alloc(mt.gpa, bound + 4);
        }
        job.dst = job.dst_buf[0..bound];
        if (job.seq_buf.len < mt.seq_capacity) {
            mt.gpa.free(job.seq_buf);
            job.seq_buf = &.{};
            job.seq_buf = try mt.gpa.alloc(ldm.RawSeq, mt.seq_capacity);
        }
    }

    /// `ZSTDMT_serialState_genSequences`, on the calling thread when the
    /// job is prepared (libzstd: in the worker, in job order): the job's
    /// long-distance matches, and the checksum over its input.
    fn serialStep(mt: *MtCtx, job: *Job) void {
        job.seqs = .{};
        if (mt.serial_ldm) |*ls| {
            job.seqs = .{ .seq = job.seq_buf[0..mt.seq_capacity] };
            ls.windowUpdate(job.src);
            ls.generateSequences(&job.seqs, job.src);
        }
        if (mt.serial_checksum and job.src.len > 0) mt.xxh.update(job.src);
    }

    /// `ZSTDMT_writeLastEmptyBlock`: a job of no input that only ends the
    /// frame, done here.
    fn writeLastEmptyBlock(mt: *MtCtx, job: *Job) void {
        _ = mt;
        std.debug.assert(job.last and !job.first and job.src.len == 0);
        job.src = &.{};
        // ZSTD_writeLastEmptyBlock: a last raw block of size 0
        job.dst[0] = 1;
        job.dst[1] = 0;
        job.dst[2] = 0;
        job.c_size.store(block_header_size, .monotonic);
        std.debug.assert(job.consumed.load(.monotonic) == 0);
    }

    fn post(mt: *MtCtx, job: *Job) bool {
        if (mt.run_inline) {
            job.run(&mt.pool.cctxs[0], null);
            return true;
        }
        return mt.pool.tryAdd(job);
    }

    /// `ZSTDMT_flushProduced`: copy out what the oldest unflushed job has
    /// produced (waiting for some, with `block`, if it has none yet), and
    /// move on once it is complete and flushed. Returns what is left in
    /// its buffer, or 1 while more is to come.
    fn flushProduced(mt: *MtCtx, output: *stream.OutBuffer, block: bool, end: stream.EndDirective) Error!usize {
        if (mt.done_job_id < mt.next_job_id) {
            const job = &mt.jobs[mt.done_job_id & mt.job_mask];
            if (block) {
                while (true) { // nothing to flush
                    const seq = job.progress.load(.acquire);
                    const consumed = job.consumed.load(.acquire);
                    if (job.dst_flushed != job.c_size.load(.acquire)) break;
                    // job is completely consumed: there will be no signal
                    if (consumed == job.src.len) break;
                    Futex.wait(&job.progress, seq);
                }
            }

            // try to flush something
            const src_consumed = job.consumed.load(.acquire);
            var c_size = job.c_size.load(.acquire);
            const src_size = job.src.len;
            if (src_consumed == src_size) if (job.err) |e| {
                // compression error detected
                mt.waitForAllJobsCompleted();
                mt.releaseAllJobResources();
                return e;
            };
            // add frame checksum if necessary (can only happen once)
            if (src_consumed == src_size and job.frame_checksum_needed) {
                const checksum: u32 = @truncate(mt.xxh.final());
                std.mem.writeInt(u32, job.dst_buf[c_size..][0..4], checksum, .little);
                c_size += 4;
                job.c_size.store(c_size, .monotonic); // the worker is no longer active
                job.frame_checksum_needed = false;
            }

            if (c_size > 0) { // compression is ongoing or completed
                const to_flush = @min(c_size - job.dst_flushed, output.dst.len - output.pos);
                @memcpy(output.dst[output.pos..][0..to_flush], job.dst_buf[job.dst_flushed..][0..to_flush]);
                output.pos += to_flush;
                job.dst_flushed += to_flush;
                if (src_consumed == src_size and job.dst_flushed == c_size) {
                    // output buffer fully flushed => free this job position
                    job.c_size.store(0, .monotonic); // considered "not started" in future check
                    mt.consumed += src_size;
                    mt.produced += c_size;
                    mt.done_job_id += 1;
                }
            }

            // how many bytes left in buffer ; fake it to 1 when unknown but >0
            if (c_size > job.dst_flushed) return c_size - job.dst_flushed;
            if (src_size > src_consumed) return 1; // current job not completely compressed
        }
        if (mt.done_job_id < mt.next_job_id) return 1; // some more jobs ongoing
        if (mt.job_ready) return 1; // one job is ready to push, just not yet in the list
        if (mt.in_filled > 0) return 1; // input is not empty, and still needs to be converted into a job
        mt.all_jobs_completed = mt.frame_ended; // all jobs are entirely flushed => if this one is last one, frame is completed
        // for ZSTD_e_end, question becomes : is frame completed ? instead of :
        // are internal buffers fully flushed ?
        if (end == .end) return @intFromBool(!mt.frame_ended);
        return 0; // internal buffers fully flushed
    }
};

/// `ZSTDMT_computeTargetJobLog`: four windows (at least 1 MB); with LDM,
/// whose window is typically oversized, from the cycle log instead.
fn computeTargetJobLog(cp: params.CParams, ldm_on: bool) u32 {
    const job_log: u32 = if (ldm_on) @max(21, params.cycleLog(cp) + 3) else @max(20, cp.window_log + 2);
    return @min(job_log, job_log_max);
}

/// `ZSTDMT_overlapLog_default`.
fn overlapLogDefault(strategy: params.Strategy) u32 {
    return switch (strategy) {
        .btultra2 => 9,
        .btultra, .btopt => 8,
        .btlazy2, .lazy2 => 7,
        .lazy, .greedy, .dfast, .fast => 6,
    };
}

/// `ZSTDMT_computeOverlapSize`: a fraction of the window (with LDM, of a
/// quarter job) given by the overlap log.
fn computeOverlapSize(cp: params.CParams, overlap_log: u32, ldm_on: bool) usize {
    const ov = if (overlap_log == 0) overlapLogDefault(cp.strategy) else overlap_log;
    const overlap_r_log: u32 = 9 - ov;
    var ov_log: u32 = if (overlap_r_log >= 8) 0 else cp.window_log - overlap_r_log;
    if (ldm_on) {
        // In Long Range Mode, the windowLog is typically oversized. In which
        // case, it's preferable to determine the jobSize based on chainLog
        // instead. Then, ovLog becomes a fraction of the jobSize, rather
        // than windowSize
        ov_log = @min(cp.window_log, computeTargetJobLog(cp, true) - 2) - overlap_r_log;
    }
    return if (ov_log == 0) 0 else @as(usize, 1) << @intCast(ov_log);
}

test "job and overlap sizes follow libzstd's formulas" {
    const cp: params.CParams = .{ .window_log = 21, .chain_log = 16, .hash_log = 17, .search_log = 1, .min_match = 5, .target_length = 0, .strategy = .dfast };
    try std.testing.expectEqual(@as(u32, 23), computeTargetJobLog(cp, false));
    try std.testing.expectEqual(@as(usize, 1) << 18, computeOverlapSize(cp, 0, false));
    try std.testing.expectEqual(@as(usize, 0), computeOverlapSize(cp, 1, false));
    try std.testing.expectEqual(@as(usize, 1) << 21, computeOverlapSize(cp, 9, false));
    // LDM: from the cycle log, and overlap log 1 is not "none" there
    try std.testing.expectEqual(@as(u32, 21), computeTargetJobLog(cp, true));
    try std.testing.expectEqual(@as(usize, 1) << 11, computeOverlapSize(cp, 1, true));
    var small = cp;
    small.window_log = 10;
    try std.testing.expectEqual(@as(u32, 20), computeTargetJobLog(small, false));
}
