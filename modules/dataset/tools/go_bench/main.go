// SPDX-License-Identifier: Apache-2.0

// Go side of `zig build bench-dataset` (modules/dataset/tools/bench.zig):
// times github.com/apache/arrow-go/v18 v18.8.0 on the table the Zig program
// describes in its header (same generator, same 20 000 rows, 6 columns), for
// the one workload named by the second argument. The first argument (work
// directory) is unused: both sides generate the table from the same formulas.
// Prints one line: name, ns/op, result count (tab-separated).
//
// Timing matches the Zig side: double the batch until it takes over 100 ms,
// then keep the best of five.
package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
)

const nrows = 20000

var sink uint64

func timeIt(f func() uint64) (float64, uint64) {
	n := 1
	for {
		t := time.Now()
		for i := 0; i < n; i++ {
			sink += f()
		}
		if time.Since(t) > 100*time.Millisecond {
			break
		}
		n *= 2
	}
	best := time.Duration(1<<63 - 1)
	var count uint64
	for k := 0; k < 5; k++ {
		t := time.Now()
		for i := 0; i < n; i++ {
			count = f()
		}
		if d := time.Since(t); d < best {
			best = d
		}
	}
	return float64(best.Nanoseconds()) / float64(n), count
}

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// The generator: identical formulas on both sides.
type raw struct {
	id    []int64
	price []float64
	name  []string
	ts    []int64
	flag  []bool
	qty   []int64
	qnull []bool
}

func gen() *raw {
	r := &raw{}
	for k := 0; k < nrows; k++ {
		i := uint64(k)
		r.id = append(r.id, int64(i))
		r.price = append(r.price, float64(i)*0.25+float64(i%97))
		r.name = append(r.name, "item-"+strconv.FormatUint((i*2654435761)%100000, 10))
		r.ts = append(r.ts, 1700000000000000+int64(i)*1000003)
		r.flag = append(r.flag, i%3 == 0)
		r.qnull = append(r.qnull, i%7 == 0)
		r.qty = append(r.qty, int64((i*37)%1000))
	}
	return r
}

var schema = arrow.NewSchema([]arrow.Field{
	{Name: "id", Type: arrow.PrimitiveTypes.Int64},
	{Name: "price", Type: arrow.PrimitiveTypes.Float64},
	{Name: "name", Type: arrow.BinaryTypes.String},
	{Name: "ts", Type: &arrow.TimestampType{Unit: arrow.Microsecond, TimeZone: "UTC"}},
	{Name: "flag", Type: arrow.FixedWidthTypes.Boolean},
	{Name: "qty", Type: arrow.PrimitiveTypes.Int64, Nullable: true},
}, nil)

// build: row by row through the record builder, the Arrow equivalent of
// Builder.appendRow.
func build(r *raw) arrow.RecordBatch {
	b := array.NewRecordBuilder(memory.NewGoAllocator(), schema)
	defer b.Release()
	b.Reserve(nrows)
	for i := 0; i < nrows; i++ {
		b.Field(0).(*array.Int64Builder).Append(r.id[i])
		b.Field(1).(*array.Float64Builder).Append(r.price[i])
		b.Field(2).(*array.StringBuilder).Append(r.name[i])
		b.Field(3).(*array.TimestampBuilder).Append(arrow.Timestamp(r.ts[i]))
		b.Field(4).(*array.BooleanBuilder).Append(r.flag[i])
		if r.qnull[i] {
			b.Field(5).(*array.Int64Builder).AppendNull()
		} else {
			b.Field(5).(*array.Int64Builder).Append(r.qty[i])
		}
	}
	return b.NewRecordBatch()
}

func encode(rec arrow.RecordBatch) []byte {
	var buf bytes.Buffer
	w := ipc.NewWriter(&buf, ipc.WithSchema(schema))
	if err := w.Write(rec); err != nil {
		die(err)
	}
	if err := w.Close(); err != nil {
		die(err)
	}
	return buf.Bytes()
}

func decode(wire []byte) arrow.RecordBatch {
	rd, err := ipc.NewReader(bytes.NewReader(wire))
	if err != nil {
		die(err)
	}
	defer rd.Release()
	if !rd.Next() {
		die(fmt.Errorf("no record"))
	}
	rec := rd.RecordBatch()
	rec.Retain()
	return rec
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go_bench WORKDIR WORKLOAD")
		os.Exit(2)
	}
	name := os.Args[2]
	fmt.Fprintf(os.Stderr, "Go %s, github.com/apache/arrow-go/v18 v18.8.0, %d rows\n", "arrow IPC stream", nrows)
	r := gen()
	rec := build(r)
	wire := encode(rec)
	tbl := decode(wire) // the table the column ops read: what came off the wire
	fmt.Fprintf(os.Stderr, "wire bytes: %d\n", len(wire))

	var f func() uint64
	switch name {
	case "build":
		f = func() uint64 {
			x := build(r)
			n := uint64(x.NumRows())
			x.Release()
			return n
		}
	case "encode":
		f = func() uint64 {
			encode(rec)
			return uint64(rec.NumRows())
		}
	case "decode":
		f = func() uint64 {
			x := decode(wire)
			n := uint64(x.NumRows())
			x.Release()
			return n
		}
	case "col_f64":
		f = func() uint64 {
			var s float64
			for _, v := range tbl.Column(1).(*array.Float64).Float64Values() {
				s += v
			}
			return uint64(s)
		}
	case "col_i64":
		f = func() uint64 {
			c := tbl.Column(5).(*array.Int64)
			var s int64
			for i := 0; i < c.Len(); i++ {
				if c.IsValid(i) {
					s += c.Value(i)
				}
			}
			return uint64(s)
		}
	case "col_text":
		f = func() uint64 {
			c := tbl.Column(2).(*array.String)
			var s uint64
			for i := 0; i < c.Len(); i++ {
				s += uint64(len(c.Value(i)))
			}
			return s
		}
	case "col_misc":
		f = func() uint64 {
			ids := tbl.Column(0).(*array.Int64).Int64Values()
			ts := tbl.Column(3).(*array.Timestamp).TimestampValues()
			fl := tbl.Column(4).(*array.Boolean)
			var s uint64
			for i := range ids {
				s += uint64(ids[i]) + uint64(ts[i])%1009
				if fl.Value(i) {
					s++
				}
			}
			return s
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown workload", name)
		os.Exit(2)
	}
	ns, count := timeIt(f)
	fmt.Printf("%s\t%.1f\t%d\n", name, ns, count)
}
