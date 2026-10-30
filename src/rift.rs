//! Rift tables: piecewise mappings between two address spaces.
//!
//! A rift table is a sorted list of entries `(left, right)`. An entry maps each address from its
//! `left` up to the next `left` to the address plus `right - left`. An address before the first
//! entry uses the offset of the last entry. An empty table maps each address to itself.
//!
//! The decoder uses rift tables for two purposes:
//!
//! - The PE preprocessing maps the RVAs of the source to the RVAs of the target.
//! - The compressor maps each target position to the source position that a source match uses.
//!
//! `msdelta.dll` computes the addresses with wrapping 64-bit arithmetic. The functions in this
//! module do the same, so they give the same tables for each input.

use crate::bits::BitReader;
use crate::int_format::IntFormat;
use crate::prelude::*;
use crate::{Error, Result};

/// One entry of a rift table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The first address of the entry.
    pub(crate) left: i64,
    /// The address that `left` maps to.
    pub(crate) right: i64,
}

impl Entry {
    /// Return the offset that the entry adds to an address.
    pub(crate) fn offset(self) -> i64 {
        self.right.wrapping_sub(self.left)
    }
}

/// A rift table, sorted by `left`. Entries with the same `left` keep their order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RiftTable {
    entries: Vec<Entry>,
}

impl RiftTable {
    /// Make an empty table.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Make a table from entries in any order.
    pub(crate) fn from_entries(mut entries: Vec<Entry>) -> Self {
        entries.sort_by_key(|entry| entry.left);
        Self { entries }
    }

    /// Return the entries.
    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Return `true` if the table has no entries.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry, and keep the table sorted.
    pub(crate) fn add(&mut self, left: i64, right: i64) {
        let entry = Entry { left, right };
        // Insert after all entries with the same `left`, as a stable sort does.
        let index = self.entries.partition_point(|e| e.left <= left);
        self.entries.insert(index, entry);
    }

    /// Append an entry. The caller sorts the table later.
    fn push(&mut self, left: i64, right: i64) {
        self.entries.push(Entry { left, right });
    }

    /// Sort the entries by `left`, with a stable sort.
    fn sort(&mut self) {
        self.entries.sort_by_key(|entry| entry.left);
    }

    /// Read a rift table with its two integer formats, as `RiftTable::FromBitReader` does.
    pub(crate) fn read(reader: &mut BitReader<'_>) -> Result<Self> {
        if !reader.bit()? {
            return Ok(Self::new());
        }
        let lefts = IntFormat::read(reader)?;
        let offsets = IntFormat::read(reader)?;
        let mut table = Self::read_entries(reader, &lefts, &offsets)?;
        table.sort();
        Ok(table)
    }

    /// Read the entries of a rift table with the given integer formats.
    fn read_entries(
        reader: &mut BitReader<'_>,
        lefts: &IntFormat,
        offsets: &IntFormat,
    ) -> Result<Self> {
        let count = reader.number64()?;
        // Each entry uses at least two bits.
        if count > reader.bits_left() / 2 {
            return Err(Error::unexpected_end().with_details("rift table entries"));
        }
        let count = usize::try_from(count).map_err(|_| Error::unexpected_end())?;
        let mut entries = Vec::with_capacity(count);
        let mut left = 0i64;
        let mut offset = 0i64;
        for _ in 0..count {
            left = left.wrapping_add(lefts.number(reader)?);
            offset = offset.wrapping_add(offsets.number(reader)?);
            entries.push(Entry {
                left,
                right: offset.wrapping_add(left),
            });
        }
        Ok(Self { entries })
    }

    /// Find the entry for `address`. Return the offset of the entry and the last address that
    /// the entry covers, as `RiftTable::GetRift` does.
    pub(crate) fn rift(&self, address: i64) -> (i64, i64) {
        let Some(first) = self.entries.first() else {
            return (0, i64::MAX);
        };
        let last = self.entries[self.entries.len() - 1];
        if address < first.left {
            return (last.offset(), first.left.wrapping_sub(1));
        }
        let index = self.entries.partition_point(|e| e.left <= address) - 1;
        let end = self
            .entries
            .get(index + 1)
            .map_or(i64::MAX, |next| next.left.wrapping_sub(1));
        (self.entries[index].offset(), end)
    }

    /// Map one address, as `RiftTable::Map` does.
    pub(crate) fn map(&self, address: i64) -> i64 {
        address.wrapping_add(self.rift(address).0)
    }

    /// Return the composition of two tables: each address maps through `a` and then `b`.
    pub(crate) fn multiply(a: &Self, b: &Self) -> Self {
        if a.is_empty() {
            return b.clone();
        }
        if b.is_empty() {
            return a.clone();
        }
        let mut out = Self::new();
        let first = a.entries[0];
        let last = a.entries[a.entries.len() - 1];
        if first.left != i64::MIN {
            // The addresses before the first entry use the offset of the last entry.
            let stop = first.left.wrapping_sub(1);
            let start = last.offset().wrapping_add(i64::MIN);
            let (rift, mut end) = b.rift(start);
            out.push(i64::MIN, rift.wrapping_add(start));
            let mut span = end.wrapping_sub(start).cast_unsigned();
            let mut left = i64::MIN;
            while stop.wrapping_sub(left).cast_unsigned() > span {
                left = left.wrapping_add_unsigned(span).wrapping_add(1);
                let address = end.wrapping_add(1);
                let (rift, next_end) = b.rift(address);
                out.push(left, rift.wrapping_add(address));
                end = next_end;
                span = end.wrapping_sub(address).cast_unsigned();
            }
        }
        for (index, entry) in a.entries.iter().enumerate() {
            let stop = match a.entries.get(index + 1) {
                // Only the last entry of a group with the same `left` counts.
                Some(next) if next.left == entry.left => continue,
                Some(next) => next.left.wrapping_sub(1),
                None => i64::MAX,
            };
            let mut left = entry.left;
            let mut address = entry.right;
            loop {
                let (rift, end) = b.rift(address);
                out.push(left, rift.wrapping_add(address));
                let span = end.wrapping_sub(address);
                if stop.wrapping_sub(left).cast_unsigned() <= span.cast_unsigned() {
                    break;
                }
                left = left.wrapping_add(span).wrapping_add(1);
                address = end.wrapping_add(1);
            }
        }
        out.sort();
        out
    }

    /// Merge two tables. For entries with the same `left`, the entries of `a` come first.
    pub(crate) fn sum(a: &Self, b: &Self) -> Self {
        if a.is_empty() {
            return b.clone();
        }
        if b.is_empty() {
            return a.clone();
        }
        let mut entries = Vec::with_capacity(a.entries.len() + b.entries.len());
        entries.extend_from_slice(&a.entries);
        entries.extend_from_slice(&b.entries);
        Self::from_entries(entries)
    }

    /// Remove the entries that do not change the mapping, as `RiftTable::InternalReduce` does.
    ///
    /// For a group of entries with the same `left`, a majority vote selects one `right`.
    pub(crate) fn reduce(&mut self) {
        let mut out: Vec<Entry> = Vec::with_capacity(self.entries.len());
        let mut index = 0;
        while let Some(&first) = self.entries.get(index) {
            let mut right = first.right;
            let mut votes = 1u32;
            index += 1;
            while let Some(entry) = self.entries.get(index).filter(|e| e.left == first.left) {
                if entry.right == right {
                    votes = votes.saturating_add(1);
                } else if votes != 0 {
                    votes -= 1;
                } else {
                    right = entry.right;
                    votes = 1;
                }
                index += 1;
            }
            let entry = Entry {
                left: first.left,
                right,
            };
            if out
                .last()
                .is_none_or(|last| last.offset() != entry.offset())
            {
                out.push(entry);
            }
        }
        if let [only] = out[..] {
            out.clear();
            if only.left != only.right {
                out.push(Entry {
                    left: 0,
                    right: only.offset(),
                });
            }
        } else if out.len() > 1 && out[0].offset() == out[out.len() - 1].offset() {
            out.remove(0);
        }
        self.entries = out;
    }

    /// Return the inverse mapping, as `RiftTable::Reverse` does.
    ///
    /// Where two ranges map to the same addresses, the range that comes first in the order of
    /// the table keeps its addresses.
    pub(crate) fn reverse(&self) -> Self {
        let entries = &self.entries;
        let Some(&first) = entries.first() else {
            return Self::new();
        };
        let mut out = Self::new();
        if entries.iter().all(|e| e.left == first.left) {
            // `msdelta.dll` keeps the offset as it is for a table with one offset.
            out.push(0, first.offset());
            return out;
        }
        let count = entries.len();
        let mut start = entries.iter().position(|e| e.left > 0).unwrap_or(count);
        if start == 0 {
            start = count;
        }
        // The image ranges that the inverse already covers, sorted: `(low, high)`.
        let mut covered: Vec<(i64, i64)> = Vec::new();
        let stop = start - 1;
        let mut current = start - 1;
        let mut next = if start < count { start } else { 0 };
        let mut position = 0i64;
        loop {
            let offset = entries[current].offset();
            let mut span = entries[next].left.wrapping_sub(position).cast_unsigned();
            let low = offset.wrapping_add(position);
            if low != i64::MIN {
                let limit = i64::MIN
                    .wrapping_sub(offset)
                    .wrapping_sub(position)
                    .cast_unsigned();
                span = span.min(limit);
            }
            if span != 0 {
                Self::reverse_range(&mut out, &mut covered, low, span, offset, position);
            }
            position = position.wrapping_add_unsigned(span);
            if position == entries[next].left {
                current = next;
                if stop == next {
                    break;
                }
                next += 1;
                if next >= count {
                    next = 0;
                }
            }
        }
        out.sort();
        out
    }

    /// Add the inverse of one range to `out`. The range starts at image address `low`, has
    /// `span` addresses, and comes from `position` with `offset`.
    fn reverse_range(
        out: &mut Self,
        covered: &mut Vec<(i64, i64)>,
        low: i64,
        span: u64,
        offset: i64,
        position: i64,
    ) {
        let mut high = low.wrapping_add_unsigned(span);
        let first = covered
            .iter()
            .position(|&(_, h)| h == i64::MIN || h >= low)
            .unwrap_or(covered.len());
        let mut end = first;
        if first < covered.len() {
            while end < covered.len() {
                if high != i64::MIN && covered[end].0 > high {
                    break;
                }
                end += 1;
            }
        }
        if first == end {
            out.push(low, position);
            covered.insert(first, (low, high));
            return;
        }
        let mut merged_low = low;
        if low >= covered[first].0 {
            merged_low = covered[first].0;
        } else {
            out.push(low, position);
        }
        for &(_, gap) in &covered[first..end - 1] {
            out.push(gap, gap.wrapping_sub(offset));
        }
        let last_high = covered[end - 1].1;
        if last_high == i64::MIN || (high != i64::MIN && last_high >= high) {
            high = last_high;
        } else {
            out.push(last_high, last_high.wrapping_sub(offset));
        }
        covered.splice(first..end, [(merged_low, high)]);
    }
}

/// A rift table in the form that the decompressor uses: each window position maps to the
/// window position of its source data with an offset.
#[derive(Debug, Clone)]
pub(crate) struct OffsetTable {
    /// The first window position of each range, with a sentinel at both ends.
    keys: Vec<u64>,
    /// The offset of each range. Zero means that the range has no source data.
    offsets: Vec<i64>,
}

impl OffsetTable {
    /// Convert a rift table, as `OffsetRiftTable<unsigned __int64>::Init` does.
    pub(crate) fn new(table: &RiftTable) -> Result<Self> {
        let entries = table.entries();
        if entries.windows(2).any(|pair| pair[0].left >= pair[1].left) {
            return Err(Error::invalid_data(
                "the rift table has two entries at one position",
            ));
        }
        let count = entries.len();
        let first_positive = entries.iter().position(|e| e.left > 0).unwrap_or(count);
        let skip_zero = first_positive != 0 && entries[first_positive - 1].left == 0;
        let ranges = count - usize::from(skip_zero);
        if ranges != 0 && first_positive == count {
            return Err(Error::invalid_data(
                "the rift table has no positive position",
            ));
        }
        let offset = |e: &Entry| {
            let fits = |value: i64| (0..=i64::from(u32::MAX)).contains(&value);
            if fits(e.left) && fits(e.left.wrapping_sub(e.right)) {
                e.right - e.left
            } else {
                0
            }
        };
        let initial = if first_positive != 0 {
            offset(&entries[first_positive - 1])
        } else {
            entries.last().map_or(0, offset)
        };
        let mut keys = Vec::with_capacity(ranges + 2);
        let mut offsets = Vec::with_capacity(ranges + 2);
        keys.push(0);
        offsets.push(initial);
        let mut index = first_positive;
        for _ in 0..ranges {
            if index >= count {
                index = 0;
            }
            keys.push(entries[index].left.cast_unsigned());
            offsets.push(offset(&entries[index]));
            index += 1;
        }
        keys.push(0);
        offsets.push(initial);
        Ok(Self { keys, offsets })
    }

    /// Return the index of the range of `position`, from the index `start` of an earlier,
    /// lower position.
    pub(crate) fn find(&self, start: usize, position: u64) -> usize {
        let mut index = start;
        while self
            .keys
            .get(index + 1)
            .is_some_and(|&key| key.wrapping_sub(1) < position)
        {
            index += 1;
        }
        index
    }

    /// Return the offset of range `index`.
    pub(crate) fn offset(&self, index: usize) -> i64 {
        self.offsets.get(index).copied().unwrap_or(0)
    }

    /// Return the first position after range `index`. The value wraps to `u64::MAX` for the
    /// last range.
    pub(crate) fn end(&self, index: usize) -> u64 {
        self.keys.get(index + 1).copied().unwrap_or(0)
    }
}
