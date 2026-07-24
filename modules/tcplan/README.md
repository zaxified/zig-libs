# tcplan

Compile a hierarchical traffic-shaping topology (site → AP → subscriber, each
with committed/ceil rates) into a deterministic, ordered plan of `tc` operations
— `mq` root, per-CPU HTB class trees, CAKE leaves and filters — honouring the
cpumap→MQ→per-CPU-HTB alignment invariant. Pure: it produces the plan; the
caller executes it via `tc` + `netlink`.

**Status:** gap (placeholder — implementation pending).
