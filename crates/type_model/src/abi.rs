// SPDX-License-Identifier: Apache-2.0
//! Target ABI model: byte order, pointer width, and C aggregate layout.
//!
//! The type model resolves C spellings to [`TypeShape`]s independently of any
//! target. This module adds the *ABI* dimension that a faithful fuzz input for a
//! non-host architecture needs: which byte order multi-byte scalars are written
//! in, and how wide a pointer is (so struct field offsets are computed for the
//! target's data model, not the x86-64 host's).
//!
//! The rules implemented here are the platform-neutral System V / GCC C ABI
//! conventions shared by every triple `resolve_cross_target` drives:
//!
//! - **Natural alignment.** A scalar of size `N` is `N`-aligned; an aggregate is
//!   aligned to its most-aligned member; its size is rounded up to that
//!   alignment (trailing padding). Arrays inherit their element's alignment.
//!   This is faithful for all supported targets — ppc/ppc64/sparc64 (SysV),
//!   mips o32/n64, aarch64/arm AAPCS, and x86-64 all align 8-byte scalars to 8
//!   within aggregates. (i386's under-alignment of `double`/`long long` to 4 is
//!   the only common exception, and i386 is not a supported cross target.)
//! - **Pointer width from the data model.** LP64 targets use an 8-byte pointer,
//!   ILP32 targets a 4-byte pointer. This is the only member size that varies
//!   across the supported targets — `type_model` already fixes `long` at 64 bits
//!   in [`crate::SCALAR_SPELLINGS`], so integer scalar widths are ABI-invariant.
//! - **`enum` is `int`-sized** (4 bytes) on all supported targets.
//!
//! Endianness never changes an offset — only the *bytes* a scalar is serialized
//! into — so [`TargetAbi::record_layout`] is byte-order independent, while
//! [`TargetAbi::encode_uint`] is byte-order dependent.

use std::fmt;

use crate::{Field, ScalarKind, TypeShape};

/// Byte order of a target ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Least-significant byte first (x86, ARM/aarch64, ppc64le, mipsel, RISC-V).
    Little,
    /// Most-significant byte first (ppc/ppc64 BE, mips BE, sparc, s390x) — the
    /// order that dominates fielded RTOS/radar systems.
    Big,
}

/// A target's byte order plus pointer width — the two ABI properties that make a
/// generated typed input or struct layout faithful to the target rather than the
/// host. Construct one with [`TargetAbi::host`] (the default, byte-for-byte the
/// current behavior) or [`TargetAbi::from_triple`] for a cross target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetAbi {
    /// Byte order for multi-byte scalars.
    pub endian: Endian,
    /// Pointer size in bytes: 8 for LP64/LLP64, 4 for ILP32.
    pub pointer_width: usize,
}

impl Default for TargetAbi {
    fn default() -> Self {
        Self::host()
    }
}

impl TargetAbi {
    /// An explicit ABI. `pointer_width` is in bytes (4 or 8 for every supported
    /// target).
    pub const fn new(endian: Endian, pointer_width: usize) -> Self {
        Self {
            endian,
            pointer_width,
        }
    }

    /// The ABI of the host BHF is running on, resolved from the build's target
    /// configuration. On the x86-64 Linux lab host this is little-endian, 8-byte
    /// pointers — so every host-lane input and layout is byte-for-byte identical
    /// to the pre-ABI behavior.
    pub fn host() -> Self {
        let endian = if cfg!(target_endian = "big") {
            Endian::Big
        } else {
            Endian::Little
        };
        Self {
            endian,
            pointer_width: std::mem::size_of::<*const u8>(),
        }
    }

    /// The ABI for a GNU target triple that `resolve_cross_target` can drive, or
    /// `None` for a triple this model does not describe. Endianness and pointer
    /// width follow the triple's canonical data model.
    pub fn from_triple(triple: &str) -> Option<Self> {
        let abi = match triple {
            // Windows x64 (LLP64): little-endian, 8-byte pointers.
            "x86_64-w64-mingw32" => Self::new(Endian::Little, 8),
            // 64-bit little-endian LP64.
            "aarch64-linux-gnu"
            | "powerpc64le-linux-gnu"
            | "x86_64-linux-gnu"
            | "x86_64-unknown-linux-gnu" => Self::new(Endian::Little, 8),
            // 64-bit big-endian LP64.
            "powerpc64-linux-gnu" | "sparc64-linux-gnu" => Self::new(Endian::Big, 8),
            // 32-bit little-endian ILP32.
            "arm-linux-gnueabihf" | "mipsel-linux-gnu" => Self::new(Endian::Little, 4),
            // 32-bit big-endian ILP32.
            "powerpc-linux-gnu" | "mips-linux-gnu" => Self::new(Endian::Big, 4),
            _ => return None,
        };
        Some(abi)
    }

    /// True when multi-byte scalars are most-significant-byte first.
    pub fn is_big_endian(&self) -> bool {
        self.endian == Endian::Big
    }

    /// Serialize the low `width` bytes of `value` in this ABI's byte order.
    /// `width` must be at most 8 (the widest scalar). Used by the typed-input
    /// generator and the target-memory coverage readers so a value lands in the
    /// bytes the target would read it from.
    pub fn encode_uint(&self, value: u64, width: usize) -> Vec<u8> {
        assert!(
            width <= 8,
            "encode_uint width {width} exceeds the 8-byte maximum scalar"
        );
        let mut bytes = value.to_le_bytes()[..width].to_vec();
        if self.is_big_endian() {
            bytes.reverse();
        }
        bytes
    }

    /// The ABI size and alignment (both in bytes) of a resolved shape.
    ///
    /// Errors — rather than silently guessing a size — when the shape has no
    /// concrete ABI size on this target: an [`TypeShape::Opaque`] type (a
    /// forward-declared aggregate, `void`, or an unknown typedef). A pointer to
    /// an opaque type is still sized (a pointer is a pointer), so only a *by
    /// value* opaque is rejected.
    pub fn size_and_align(&self, shape: &TypeShape) -> Result<(usize, usize), AbiLayoutError> {
        match shape {
            TypeShape::Scalar(kind) => {
                let size = scalar_size(*kind);
                Ok((size, size))
            }
            // A C `enum` has `int` (4-byte) size/alignment on every supported target.
            TypeShape::Enum { .. } => Ok((4, 4)),
            // Strings, data pointers, and function pointers are all one pointer
            // wide — the only member size that varies with the data model.
            TypeShape::CString | TypeShape::Pointer(_) | TypeShape::FuncPtr => {
                Ok((self.pointer_width, self.pointer_width))
            }
            TypeShape::Array { elem, len } => {
                let (elem_size, elem_align) = self.size_and_align(elem)?;
                Ok((elem_size.saturating_mul(*len), elem_align))
            }
            TypeShape::Struct { fields, .. } => {
                let layout = self.struct_layout(fields)?;
                Ok((layout.size, layout.align))
            }
            TypeShape::Union { fields, .. } => {
                let layout = self.union_layout(fields)?;
                Ok((layout.size, layout.align))
            }
            TypeShape::Opaque(spelling) => Err(AbiLayoutError::UnsizedType {
                spelling: spelling.clone(),
            }),
        }
    }

    /// The concrete field offsets, size, and alignment of a struct or union
    /// shape, computed for this ABI's data model. This is the pointer-width
    /// dependent layout: an LP64 target and an ILP32 target lay the same struct
    /// out differently wherever a pointer (or a member that transitively
    /// contains one) participates.
    pub fn record_layout(&self, shape: &TypeShape) -> Result<RecordLayout, AbiLayoutError> {
        match shape {
            TypeShape::Struct { fields, .. } => self.struct_layout(fields),
            TypeShape::Union { fields, .. } => self.union_layout(fields),
            other => Err(AbiLayoutError::NotARecord {
                shape: format!("{other:?}"),
            }),
        }
    }

    fn struct_layout(&self, fields: &[Field]) -> Result<RecordLayout, AbiLayoutError> {
        let mut offset = 0usize;
        let mut max_align = 1usize;
        let mut placed = Vec::with_capacity(fields.len());
        for field in fields {
            let (size, align) = self.size_and_align(&field.shape)?;
            offset = round_up(offset, align);
            placed.push(FieldLayout {
                name: field.name.clone(),
                offset,
                size,
                align,
            });
            offset = offset.saturating_add(size);
            max_align = max_align.max(align);
        }
        Ok(RecordLayout {
            fields: placed,
            size: round_up(offset, max_align),
            align: max_align,
        })
    }

    fn union_layout(&self, fields: &[Field]) -> Result<RecordLayout, AbiLayoutError> {
        let mut max_size = 0usize;
        let mut max_align = 1usize;
        let mut placed = Vec::with_capacity(fields.len());
        for field in fields {
            let (size, align) = self.size_and_align(&field.shape)?;
            placed.push(FieldLayout {
                name: field.name.clone(),
                offset: 0,
                size,
                align,
            });
            max_size = max_size.max(size);
            max_align = max_align.max(align);
        }
        Ok(RecordLayout {
            fields: placed,
            size: round_up(max_size, max_align),
            align: max_align,
        })
    }
}

/// The placement of one field within a [`RecordLayout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLayout {
    pub name: String,
    /// Byte offset from the start of the record.
    pub offset: usize,
    /// Size of the field in bytes.
    pub size: usize,
    /// Alignment of the field in bytes.
    pub align: usize,
}

/// The computed layout of a struct or union for a specific [`TargetAbi`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLayout {
    pub fields: Vec<FieldLayout>,
    /// Total size in bytes, including trailing padding to the record's alignment.
    pub size: usize,
    /// Alignment in bytes (the maximum member alignment).
    pub align: usize,
}

/// Why a shape could not be laid out for a target ABI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiLayoutError {
    /// A member (possibly nested) resolved to a type with no ABI-defined size on
    /// this target — an opaque/forward-declared aggregate, `void`, or an unknown
    /// typedef. A faithful layout is impossible without a concrete definition.
    UnsizedType { spelling: String },
    /// [`TargetAbi::record_layout`] was called on a shape that is not a struct or
    /// union.
    NotARecord { shape: String },
}

impl fmt::Display for AbiLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiLayoutError::UnsizedType { spelling } => write!(
                f,
                "type `{spelling}` has no ABI-defined size on this target \
                 (opaque, void, or an unresolved typedef); a faithful layout \
                 requires a concrete definition"
            ),
            AbiLayoutError::NotARecord { shape } => {
                write!(
                    f,
                    "record_layout requires a struct or union shape, got {shape}"
                )
            }
        }
    }
}

impl std::error::Error for AbiLayoutError {}

/// The fixed byte width of a scalar. Integer/float widths are ABI-invariant
/// across every supported target (`type_model` fixes `long` at 64 bits), so this
/// takes no ABI.
pub fn scalar_size(kind: ScalarKind) -> usize {
    match kind {
        ScalarKind::Bool | ScalarKind::I8 | ScalarKind::U8 => 1,
        ScalarKind::I16 | ScalarKind::U16 => 2,
        ScalarKind::I32 | ScalarKind::U32 | ScalarKind::F32 => 4,
        ScalarKind::I64 | ScalarKind::U64 | ScalarKind::F64 => 8,
    }
}

/// Round `value` up to the next multiple of `align` (a power of two in practice).
fn round_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        return value;
    }
    value.div_ceil(align).saturating_mul(align)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(name: &str, shape: TypeShape) -> Field {
        Field {
            name: name.to_owned(),
            shape,
            c_type: name.to_owned(),
        }
    }

    #[test]
    fn host_abi_matches_the_x86_64_lab_host() {
        // The host default must be little-endian, 8-byte pointers so every
        // existing host-lane input and layout is unchanged.
        let host = TargetAbi::host();
        assert_eq!(host.endian, Endian::Little);
        assert_eq!(host.pointer_width, 8);
        assert!(!host.is_big_endian());
        assert_eq!(TargetAbi::default(), host);
    }

    #[test]
    fn triples_resolve_to_their_canonical_data_model() {
        for (triple, endian, width) in [
            ("x86_64-w64-mingw32", Endian::Little, 8),
            ("aarch64-linux-gnu", Endian::Little, 8),
            ("powerpc64le-linux-gnu", Endian::Little, 8),
            ("powerpc64-linux-gnu", Endian::Big, 8),
            ("sparc64-linux-gnu", Endian::Big, 8),
            ("arm-linux-gnueabihf", Endian::Little, 4),
            ("mipsel-linux-gnu", Endian::Little, 4),
            ("powerpc-linux-gnu", Endian::Big, 4),
            ("mips-linux-gnu", Endian::Big, 4),
        ] {
            let abi = TargetAbi::from_triple(triple).unwrap_or_else(|| panic!("{triple} resolves"));
            assert_eq!(abi.endian, endian, "{triple} endian");
            assert_eq!(abi.pointer_width, width, "{triple} width");
        }
        assert_eq!(TargetAbi::from_triple("s390x-linux-gnu"), None);
        assert_eq!(TargetAbi::from_triple("nonsense"), None);
    }

    #[test]
    fn encode_uint_reverses_only_for_big_endian() {
        let le = TargetAbi::new(Endian::Little, 8);
        let be = TargetAbi::new(Endian::Big, 8);
        // Golden: 0x03040506 as a 4-byte field.
        assert_eq!(le.encode_uint(0x0304_0506, 4), vec![0x06, 0x05, 0x04, 0x03]);
        assert_eq!(be.encode_uint(0x0304_0506, 4), vec![0x03, 0x04, 0x05, 0x06]);
        // A single byte is order-independent.
        assert_eq!(le.encode_uint(0xAB, 1), vec![0xAB]);
        assert_eq!(be.encode_uint(0xAB, 1), vec![0xAB]);
    }

    /// GOLDEN VECTOR — pointer-width-dependent struct layout.
    ///
    /// ```c
    /// struct radar_hdr {
    ///     uint8_t version;   // 1 byte
    ///     void   *payload;   // pointer  (width varies by data model)
    ///     uint32_t seq;      // 4 bytes
    /// };
    /// ```
    ///
    /// LP64 (ppc64/aarch64/x86-64, pointer 8):
    ///   version @0 (1); pad 7; payload @8 (8); seq @16 (4); pad 4 → size 24, align 8.
    /// ILP32 (ppc/mips/arm, pointer 4):
    ///   version @0 (1); pad 3; payload @4 (4); seq @8 (4)          → size 12, align 4.
    ///
    /// The offsets themselves move with the pointer width — proof that no
    /// host-word-size assumption leaks into the layout.
    #[test]
    fn struct_layout_is_pointer_width_correct() {
        let radar_hdr = TypeShape::Struct {
            name: "radar_hdr".to_owned(),
            fields: vec![
                field("version", TypeShape::Scalar(ScalarKind::U8)),
                field(
                    "payload",
                    TypeShape::Pointer(Box::new(TypeShape::Opaque("void".to_owned()))),
                ),
                field("seq", TypeShape::Scalar(ScalarKind::U32)),
            ],
        };

        let lp64 = TargetAbi::from_triple("powerpc64-linux-gnu").unwrap();
        let layout = lp64.record_layout(&radar_hdr).expect("lp64 layout");
        assert_eq!(
            layout.fields.iter().map(|f| f.offset).collect::<Vec<_>>(),
            vec![0, 8, 16]
        );
        assert_eq!(layout.size, 24);
        assert_eq!(layout.align, 8);
        // A pointer BY VALUE is sized even though it points at an opaque type.
        assert_eq!(layout.fields[1].size, 8);

        let ilp32 = TargetAbi::from_triple("powerpc-linux-gnu").unwrap();
        let layout = ilp32.record_layout(&radar_hdr).expect("ilp32 layout");
        assert_eq!(
            layout.fields.iter().map(|f| f.offset).collect::<Vec<_>>(),
            vec![0, 4, 8]
        );
        assert_eq!(layout.size, 12);
        assert_eq!(layout.align, 4);
        assert_eq!(layout.fields[1].size, 4);
    }

    /// GOLDEN VECTOR — byte-order-dependent struct image.
    ///
    /// ```c
    /// struct msg { uint16_t kind; uint32_t len; };   // kind @0, len @4, size 8
    /// ```
    /// Instance: kind = 0x0102, len = 0x03040506.
    ///
    /// LE (host/ppc64le): 02 01 00 00 06 05 04 03
    /// BE (ppc64):        01 02 00 00 03 04 05 06
    ///
    /// Offsets are identical (both LP64); only the multi-byte fields reverse.
    #[test]
    fn struct_image_is_emitted_in_target_byte_order() {
        let msg = TypeShape::Struct {
            name: "msg".to_owned(),
            fields: vec![
                field("kind", TypeShape::Scalar(ScalarKind::U16)),
                field("len", TypeShape::Scalar(ScalarKind::U32)),
            ],
        };

        let image = |abi: TargetAbi| -> Vec<u8> {
            let layout = abi.record_layout(&msg).expect("layout");
            assert_eq!(
                layout.fields.iter().map(|f| f.offset).collect::<Vec<_>>(),
                vec![0, 4],
                "offsets are byte-order independent"
            );
            let mut bytes = vec![0u8; layout.size];
            let values = [0x0102u64, 0x0304_0506u64];
            for (field, value) in layout.fields.iter().zip(values) {
                bytes[field.offset..field.offset + field.size]
                    .copy_from_slice(&abi.encode_uint(value, field.size));
            }
            bytes
        };

        let le = image(TargetAbi::from_triple("powerpc64le-linux-gnu").unwrap());
        let be = image(TargetAbi::from_triple("powerpc64-linux-gnu").unwrap());
        assert_eq!(le, vec![0x02, 0x01, 0x00, 0x00, 0x06, 0x05, 0x04, 0x03]);
        assert_eq!(be, vec![0x01, 0x02, 0x00, 0x00, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn array_and_nested_aggregate_sizes_follow_the_abi() {
        // char name[16] — 16 bytes, align 1 regardless of ABI.
        let arr = TypeShape::Array {
            elem: Box::new(TypeShape::Scalar(ScalarKind::I8)),
            len: 16,
        };
        let host = TargetAbi::host();
        assert_eq!(host.size_and_align(&arr).unwrap(), (16, 1));

        // A struct containing a pointer array sizes the array by pointer width.
        let ptr_array = TypeShape::Struct {
            name: "table".to_owned(),
            fields: vec![field(
                "slots",
                TypeShape::Array {
                    elem: Box::new(TypeShape::FuncPtr),
                    len: 4,
                },
            )],
        };
        assert_eq!(
            TargetAbi::from_triple("powerpc64-linux-gnu")
                .unwrap()
                .record_layout(&ptr_array)
                .unwrap()
                .size,
            32
        );
        assert_eq!(
            TargetAbi::from_triple("powerpc-linux-gnu")
                .unwrap()
                .record_layout(&ptr_array)
                .unwrap()
                .size,
            16
        );
    }

    #[test]
    fn opaque_by_value_field_is_a_descriptive_error() {
        let bad = TypeShape::Struct {
            name: "bad".to_owned(),
            fields: vec![field(
                "body",
                TypeShape::Opaque("struct forward".to_owned()),
            )],
        };
        let err = TargetAbi::host().record_layout(&bad).unwrap_err();
        assert_eq!(
            err,
            AbiLayoutError::UnsizedType {
                spelling: "struct forward".to_owned()
            }
        );
        assert!(err.to_string().contains("struct forward"));

        // A non-record shape is rejected distinctly.
        let not_record = TargetAbi::host().record_layout(&TypeShape::Scalar(ScalarKind::I32));
        assert!(matches!(not_record, Err(AbiLayoutError::NotARecord { .. })));
    }
}
