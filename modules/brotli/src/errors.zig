//! Typed error set for the Brotli codec. Malformed input is always reported as
//! one of these errors — the decoder never panics on hostile input.

pub const BrotliError = error{
    /// Input ended before a complete stream was decoded.
    TruncatedInput,
    /// A reserved bit / field had a non-zero (illegal) value.
    ReservedBitSet,
    /// Window-bits field encodes an invalid value.
    InvalidWindowBits,
    /// A meta-block length nibble/byte violated the "no leading zero" rule.
    InvalidLength,
    /// Padding bits before a byte boundary were not zero.
    InvalidPadding,
    /// A prefix (Huffman) code was malformed (over/under-subscribed, bad symbol).
    InvalidHuffman,
    /// A simple prefix code repeated a symbol.
    DuplicateSimpleSymbol,
    /// A context map RLE run overflowed the map.
    InvalidContextMap,
    /// A backward reference pointed before the start of the output.
    InvalidDistance,
    /// A static-dictionary reference was out of range / had a bad transform.
    InvalidDictionary,
    /// Decoded output would exceed the configured `max_output` cap.
    OutputTooLarge,
    /// Trailing garbage after the final meta-block.
    TrailingData,
    /// Allocation failed.
    OutOfMemory,
};
