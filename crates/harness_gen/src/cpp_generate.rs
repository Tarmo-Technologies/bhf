// SPDX-License-Identifier: Apache-2.0

use crate::c_decoders::CParamEmission;
pub use crate::cpp_decoders::CppDecoderLimits;
use crate::cpp_decoders::{select_cpp_decoder, select_cpp_decoder_with_registry_limited};
// `select_cpp_decoder` (the default-limits probe at `cpp_parameter_type_supported`)
// is intentionally still used; the limits-aware variant drives actual emission.
use crate::templates;
use crate::HarnessGenError;
use cpp_parser::CppFunction;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use type_model::TypeRegistry;

const BUILD_CONTEXT_PROVENANCE_PREFIX: &str = "@bhf-build-context-provenance=";
const BUILD_CONTEXT_CONFIDENCE_PREFIX: &str = "@bhf-build-context-confidence=";
const BUILD_CONTEXT_RECOVERY_PREFIX: &str = "@bhf-build-context-recovery=";
const BUILD_CONTEXT_LDFLAG_PREFIX: &str = "@bhf-build-context-ldflag=";
const BUILD_CONTEXT_CXX_STANDARD_PREFIX: &str = "@bhf-build-context-cxx-standard=";
const BUILD_CONTEXT_COMPILER_PREFIX: &str = "@bhf-build-context-compiler=";
const BUILD_CONTEXT_DROPPED_PREFIX: &str = "@bhf-build-context-dropped=";

#[derive(Debug, Clone)]
pub struct CppParameter {
    pub name: String,
    pub cpp_type: String,
}

/// Factory construction plan: the receiver is obtained by calling a factory
/// method on an owner object (or a free function) rather than by direct construction.
/// The owner is stack-allocated and kept alive for the entire method call so the
/// receiver's lifetime (which may be owned by the factory owner) is safe.
#[derive(Debug, Clone)]
pub struct CppFactoryPlan {
    /// The qualified type of the factory owner (e.g., `"tinyxml2::XMLDocument"`),
    /// or `None` when the factory is a free function (no owner needed).
    pub owner_type: Option<String>,
    /// `true` when the owner method is static and must be called as
    /// `Owner::Factory(...)` without constructing an owner instance.
    pub owner_method_is_static: bool,
    /// The factory method name (instance method) or free-function name.
    pub factory_method: String,
    /// Parameters to pass to the factory call (decoded from fuzz input).
    pub factory_params: Vec<CppParameter>,
    /// Whether the factory returns a pointer (`C*`, `unique_ptr<C>`, `shared_ptr<C>`)
    /// requiring `->` access and a null guard; `false` for value or reference returns.
    pub receiver_is_pointer: bool,
}

#[derive(Debug, Clone)]
pub struct GenerateCppDirectArgs {
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub target: CppFunction,
    pub params: Vec<CppParameter>,
    pub return_type: String,
    pub target_includes: Vec<String>,
    pub target_includes_dirs: Vec<PathBuf>,
    pub target_sources: Vec<PathBuf>,
    pub compile_flags: Vec<String>,
    pub c_runtime_include: PathBuf,
    /// Namespaces to inject as `using namespace X;` before the harness body
    /// so unqualified class names from the project header resolve.
    /// Populated by CLI auto-detection (scan included headers for top-level
    /// `namespace X { ... }` blocks).
    pub using_namespaces: Vec<String>,
    /// User-supplied cleanup expression to emit after the target call.
    /// `R` is bound to the target's return value. Mirrors the C-side
    /// `result_cleanup` so callers fuzzing C++ libraries with leaky
    /// factories can pass `--cleanup "delete R"` etc.
    pub result_cleanup: Option<String>,
    pub constructor_params: Vec<CppParameter>,
    pub type_defs: Vec<c_parser::CTypeDefs>,
    /// C++ classes the caller determined are default-constructible, so a
    /// class-typed constructor argument can be default-constructed and passed
    /// rather than skipping the whole constructor (#353).
    pub default_constructible_classes: Vec<String>,
    /// #99: declaration-aware construction recipes for opaque class PARAMETERS
    /// that are not default-constructible but can be built via a public factory or
    /// parameterized constructor resolved from the owning header. Keyed by
    /// canonical class spelling. Empty when every parameter is directly decodable.
    pub parameter_constructions: Vec<(String, type_model::ClassConstruction)>,
    /// When the method's declaring class is ABSTRACT, the concrete subclass to
    /// build the receiver from instead (`MemoryReader` for an abstract `Reader`),
    /// so `<override> _bhf_receiver; _bhf_receiver.method(..)` calls the virtual
    /// method polymorphically. `None` keeps the declaring class (#456).
    pub receiver_class_override: Option<String>,
    /// Factory construction plan when the declaring class has no usable public
    /// constructor but can be obtained via a factory method or free function.
    /// Overrides `constructor_params` / `receiver_class_override` when present.
    pub factory_plan: Option<CppFactoryPlan>,
    /// Configurable container/bitset/array decoder caps (§27.11). `Default`
    /// reproduces the historical hardcoded behavior; the CLI threads
    /// `--container-size-max` / `--bitset-max-size` / `--array-max-size` here.
    pub decoder_limits: CppDecoderLimits,
    /// Force-fuzz mode (`auto --force`). When true, a parameter the type-directed
    /// decoders reject is given a best-effort compiling driver
    /// ([`crate::c_decoders::best_effort_param_emission`]) instead of failing the
    /// whole target. Default `false` leaves the emission byte-for-byte unchanged.
    pub force: bool,
}

#[derive(Debug, Clone)]
pub struct CppLifecycleStep {
    pub name: String,
    pub params: Vec<CppParameter>,
    pub return_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CppProtocolArg {
    Decode,
    InputData,
    InputSize,
    Literal(String),
}

/// A declaration-checked member call observed in a maintained test/fuzzer.
/// Unlike the random lifecycle suffix, protocol steps are emitted once in their
/// observed order and can retain input bindings and literal state transitions.
#[derive(Debug, Clone)]
pub struct CppProtocolStep {
    pub step: CppLifecycleStep,
    pub args: Vec<CppProtocolArg>,
    pub marks_target: bool,
}

#[derive(Debug, Clone)]
pub struct GenerateCppSequenceArgs {
    pub harness_id: String,
    pub output_dir: PathBuf,
    pub source_path: PathBuf,
    pub target: CppFunction,
    pub params: Vec<CppParameter>,
    pub return_type: String,
    pub target_includes: Vec<String>,
    pub target_includes_dirs: Vec<PathBuf>,
    pub target_sources: Vec<PathBuf>,
    pub compile_flags: Vec<String>,
    pub c_runtime_include: PathBuf,
    pub using_namespaces: Vec<String>,
    pub result_cleanup: Option<String>,
    pub constructor_params: Vec<CppParameter>,
    pub lifecycle_steps: Vec<CppLifecycleStep>,
    pub protocol_steps: Vec<CppProtocolStep>,
    pub type_defs: Vec<c_parser::CTypeDefs>,
    /// See `GenerateCppDirectArgs::default_constructible_classes` (#353).
    pub default_constructible_classes: Vec<String>,
    /// See `GenerateCppDirectArgs::parameter_constructions` (#99).
    pub parameter_constructions: Vec<(String, type_model::ClassConstruction)>,
    /// See `GenerateCppDirectArgs::receiver_class_override` (#456).
    pub receiver_class_override: Option<String>,
    /// See `GenerateCppDirectArgs::factory_plan`.
    pub factory_plan: Option<CppFactoryPlan>,
    /// See `GenerateCppDirectArgs::decoder_limits` (§27.11).
    pub decoder_limits: CppDecoderLimits,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GeneratedCppFiles {
    pub main_cpp: PathBuf,
    pub makefile: PathBuf,
    pub harness_id: String,
}

/// On Windows, prepend the MSVC STL version-mismatch escape hatch to the C++
/// harness compile flags. The Microsoft STL shipped with Visual Studio hard-errors
/// (`STL1000: Unexpected compiler version`) when the compiler predates the
/// clang/MSVC version it was tested against — and clang routinely lags the latest
/// VS STL by a release (e.g. clang 18 vs an STL demanding clang 19), so every C++
/// harness fails to compile against a recent VS STL. `_ALLOW_COMPILER_AND_STL_
/// VERSION_MISMATCH` is Microsoft's supported opt-out. No-op off Windows (libstdc++
/// / libc++ ignore it). Pure (platform passed in) so it is unit-testable off-Windows.
fn cpp_compile_flags_with_stl_compat(mut flags: Vec<String>, windows: bool) -> Vec<String> {
    const STL_COMPAT: &str = "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH";
    if windows && !flags.iter().any(|f| f == STL_COMPAT) {
        flags.insert(0, STL_COMPAT.to_owned());
    }
    flags
}

pub fn generate_cpp_direct_harness(
    args: GenerateCppDirectArgs,
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let context = build_cpp_context(&args, &[])?;
    render_cpp_harness(
        &args.output_dir,
        &args.harness_id,
        &context,
        &args.c_runtime_include,
    )
}

/// Like [`generate_cpp_direct_harness`] but constructs opaque-handle parameters
/// through the given init/delete FREE-function lifecycles (the CLI discovers them
/// from sibling functions). Lets a C-ABI decode entry whose first parameter is an
/// opaque context — libde265 `de265_decode_data(de265_decoder_context *, const
/// void *, int)` — be auto-harnessed: `ctx = de265_new_decoder(); decode(ctx,
/// Data, Size); de265_free_decoder(ctx);`.
pub fn generate_cpp_direct_harness_with_lifecycle(
    args: GenerateCppDirectArgs,
    handle_lifecycle: &[crate::c_decoders::CHandleLifecycle],
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let context = build_cpp_context(&args, handle_lifecycle)?;
    render_cpp_harness(
        &args.output_dir,
        &args.harness_id,
        &context,
        &args.c_runtime_include,
    )
}

pub fn generate_cpp_sequence_harness(
    args: GenerateCppSequenceArgs,
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let context = build_cpp_sequence_context(&args)?;
    render_cpp_harness(
        &args.output_dir,
        &args.harness_id,
        &context,
        &args.c_runtime_include,
    )
}

pub fn cpp_parameter_type_supported(cpp_type: &str) -> bool {
    select_cpp_decoder(cpp_type, "_bhf_probe").is_some()
}

/// Registry-aware counterpart used by lifecycle planning. Candidate selection
/// must consult the same aliases, visible aggregates, containers, and verified
/// default-constructible classes as final emission; otherwise valid setup
/// methods are dropped before codegen ever gets a chance to decode them.
pub fn cpp_parameter_type_supported_with_registry(
    cpp_type: &str,
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> bool {
    select_cpp_decoder_with_registry_limited(cpp_type, "_bhf_probe", registry, limits).is_ok()
}

fn cpp_lexical_lookup_scopes(target: &CppFunction) -> Vec<String> {
    (1..=target.qualifier_path.len())
        .rev()
        .map(|length| target.qualifier_path[..length].join("::"))
        .collect()
}

/// Whether `name` is something we can legally write after `receiver.` as a member
/// call — a plain member identifier or an `operatorX` overload. Robustness gate for
/// the sequence/method emitter (campaign: tinyobjloader): even after attribution is
/// fixed in the parser, a residual tree-sitter error-recovery artifact must never
/// reach codegen as `receiver.<garbage>(...)`. A `~Dtor`, a qualified `A::b`, a
/// templated `f<...>` spelling, or any non-identifier text is rejected here and the
/// step/target is dropped or the harness skipped cleanly instead of emitting a
/// non-compiling call.
pub fn cpp_callable_member_name(name: &str) -> bool {
    let name = name.trim();
    if let Some(op) = name.strip_prefix("operator") {
        // `operator==`, `operator()`, `operator[]`, `operator new` …: accept any
        // non-empty operator spelling; reject a bare `operator`.
        return !op.is_empty();
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Reserved keywords that can NEVER stand alone as a return type. A
/// `function_definition` tree-sitter recovered from a mis-parsed `namespace X {`
/// surfaces with return type exactly `namespace` (tinyobjloader's `detail_fp`),
/// which the emitter would otherwise render as the un-compilable
/// `namespace R = receiver.detail_fp();`. (`struct`/`class`/`enum`/`union` are NOT
/// listed: as a *single* leading token before a tag name — `struct Foo` — they are
/// a legal elaborated-type-specifier, so a lone one is the artifact while two
/// tokens are fine.)
const CPP_NON_TYPE_RETURN_KEYWORDS: &[&str] = &[
    "namespace",
    "template",
    "typedef",
    "using",
    "friend",
    "public",
    "private",
    "protected",
    "return",
];

/// Whether `return_type` is a usable type the emitter can write as `<ret> R = …`.
/// Rejects the empty string only implicitly (callers treat empty as `void`); the
/// real job is vetoing a lone reserved keyword that is a parse artifact rather than
/// a type. See [`CPP_NON_TYPE_RETURN_KEYWORDS`].
pub fn cpp_return_type_emittable(return_type: &str) -> bool {
    let toks: Vec<&str> = return_type.split_whitespace().collect();
    if let [only] = toks.as_slice() {
        if CPP_NON_TYPE_RETURN_KEYWORDS.contains(only) {
            return false;
        }
    }
    true
}

fn render_cpp_harness(
    output_dir: &PathBuf,
    harness_id: &str,
    context: &CppTemplateContext,
    c_runtime_include: &Path,
) -> Result<GeneratedCppFiles, HarnessGenError> {
    let tera = templates::build_tera()?;
    let main_cpp = tera.render(
        "direct_harness_cpp",
        &crate::c_generate::harness_source_context(context)?,
    )?;
    let makefile = tera.render(
        "harness_makefile_cpp",
        &crate::c_generate::harness_makefile_context(context, c_runtime_include)?,
    )?;

    fs::create_dir_all(output_dir)?;
    let main_path = output_dir.join("main.cpp");
    let makefile_path = output_dir.join("Makefile");
    fs::write(&main_path, main_cpp)?;
    fs::write(&makefile_path, makefile)?;
    context.arg_layout.write(output_dir)?;
    // Portable-harness export (Mayhem / libFuzzer / AFL++ / honggfuzz). The C++
    // default binary (`main`) reads argv[1] as a file; the Makefile offers
    // `make libfuzzer` / `make afl`.
    crate::portability::write_artifacts(
        output_dir,
        &crate::portability::PortabilitySpec {
            harness_id: harness_id.to_owned(),
            lane: crate::portability::Lane::Cpp,
            binary: "main".to_owned(),
            input: crate::portability::InputDelivery::File,
            sanitizer: true,
            libfuzzer_binary: Some("main_libfuzzer".to_owned()),
            afl_binary: Some("main_afl".to_owned()),
            crash_on_finding_env: false,
            passthrough_entrypoint: context.passthrough_libfuzzer_entrypoint,
        },
    )?;

    Ok(GeneratedCppFiles {
        main_cpp: main_path,
        makefile: makefile_path,
        harness_id: harness_id.to_owned(),
    })
}

#[derive(Debug, Serialize)]
struct CppTemplateContext {
    /// Written to `arg-layout.json`; not a template variable.
    #[serde(skip)]
    arg_layout: crate::arg_layout::ArgLayout,
    harness_id: String,
    qualified_target_name: String,
    /// Exact public RE2 parser lifecycle: whole-input string view, canonical
    /// parser flags, caller-owned status, and intrusive result release.
    expert_re2_parse: bool,
    /// Turbofish type-argument suffix for an instantiated template target —
    /// `"<int>"`, `"<std::string, double>"`, or empty for a non-template
    /// (#455 / §27.5). Appended directly after `qualified_target_name` in the
    /// emitted call so the right specialization is selected.
    target_template_suffix: String,
    target_name: String,
    forward_namespace: String,
    /// The return type as the FORWARD DECLARATION must spell it: the target's
    /// return type with any export/calling-convention decoration removed.
    /// `JNIEXPORT jstring` is valid where the project's own headers define
    /// `JNIEXPORT`, but the harness does not see them, so copying it verbatim
    /// manufactures `unknown type name 'JNIEXPORT'` — an error the target did not
    /// have. The C lane strips the same shape via `unwrap_export_macro`.
    forward_return_type: String,
    /// Exact (template-substituted) parameter spellings from the parsed target
    /// declaration. Decoder emissions intentionally erase references/cv details;
    /// reusing them in a forward declaration creates a different overload.
    forward_param_types: Vec<String>,
    target_includes: Vec<String>,
    target_includes_dirs: Vec<String>,
    target_sources: Vec<String>,
    compile_flags: Vec<String>,
    link_flags: Vec<String>,
    build_context_provenance: String,
    build_context_confidence: String,
    build_context_recovery: String,
    build_context_dropped: String,
    cxx_compiler: String,
    /// The C driver paired with `cxx_compiler`, the Makefile's default `CC`
    /// for C translation units of the compile database.
    c_compiler: String,
    /// Flag family the Makefile falls back to when it cannot ask `$(CXX)`.
    cxx_compiler_family: String,
    c_runtime_include: String,
    params: Vec<CParamEmission>,
    /// The target parameters' decode statements, in decode order, with the
    /// position captures and argument-trace statements (see
    /// [`crate::arg_trace`]); and the after-call trace statements.
    params_decode: Vec<String>,
    /// The target's whole-input parameters, decoded right before the call
    /// when other arguments are decoded in between (see
    /// [`crate::arg_trace::Group::defer_input`]).
    params_late: Vec<String>,
    params_after: Vec<String>,
    /// A borrowed Pugixml in-place buffer must outlive the document's parse tree.
    pugi_retained_buffers: bool,
    return_type: String,
    return_type_present: bool,
    constructor_params: Vec<CParamEmission>,
    /// [`Self::params_decode`] for the receiver's constructor arguments.
    constructor_decode: Vec<String>,
    /// The trace statement describing the constructed receiver object.
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_trace: Option<String>,
    /// Class name (heuristically detected) when the target is a member
    /// function and we should emit a stack instance + method call instead
    /// of a free-function forward decl.
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_class: Option<String>,
    /// True when the target itself is a constructor: emit direct-initialization
    /// `Class _bhf_receiver(args);` rather than a member call `_bhf_receiver.Class(args)`
    /// (naming a constructor as a member function is illegal C++).
    target_is_constructor: bool,
    /// Static methods have no receiver object, but they are still class members
    /// and cannot be forward-declared as namespace-level free functions.
    target_is_method: bool,
    /// True when at least one header in `target_includes` actually DECLARES the
    /// target, so the forward declaration block is redundant (and would conflict
    /// for class members).
    ///
    /// This is a statement about the target, not about the include list. A
    /// header-less `.cpp` free function still pulls in whatever headers the file
    /// includes, and taking their mere presence as proof of declaration left the
    /// harness calling a name nothing had declared — `use of undeclared
    /// identifier`, the third-largest residual build-error class in the forced
    /// sweep.
    has_target_header: bool,
    using_namespaces: Vec<String>,
    uses_array: bool,
    uses_bitset: bool,
    uses_chrono: bool,
    uses_deque: bool,
    uses_filesystem: bool,
    uses_forward_list: bool,
    uses_functional: bool,
    uses_list: bool,
    uses_map: bool,
    uses_memory: bool,
    uses_optional: bool,
    uses_set: bool,
    uses_span: bool,
    uses_tuple: bool,
    uses_unordered_map: bool,
    uses_unordered_set: bool,
    uses_utility: bool,
    uses_variant: bool,
    cxx_standard: String,
    passthrough_libfuzzer_entrypoint: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_cleanup: Option<String>,
    lifecycle_steps: Vec<CppLifecycleStepEmission>,
    lifecycle_step_count: usize,
    protocol_steps: Vec<CppProtocolStepEmission>,
    /// True for a free-function byte-stream decoder (`decode(uint8_t byte, ...)`,
    /// PX4 st24_decode/sumd_decode): feed the whole fuzz input through the target
    /// one byte at a time so the stateful protocol machine is driven. `params`
    /// then holds only parameters 2..N (the byte is the loop variable).
    byte_stream: bool,
    /// Factory-based receiver construction, set when the receiver class has no
    /// usable public constructor and is instead built via a factory method or
    /// free function. When present, the template emits owner construction +
    /// factory call + null-guarded method call instead of the normal receiver path.
    #[serde(skip_serializing_if = "Option::is_none")]
    factory: Option<CppTemplateFactoryContext>,
}

#[derive(Debug, Serialize)]
struct CppLifecycleStepEmission {
    name: String,
    params: Vec<CParamEmission>,
    /// Decode and argument-trace statements (see [`crate::arg_trace`]).
    decode: Vec<String>,
    after: Vec<String>,
    return_type: String,
    return_type_present: bool,
    result_name: String,
}

#[derive(Debug, Serialize)]
struct CppProtocolStepEmission {
    /// The step's decode layout (see [`crate::arg_layout`]).
    #[serde(skip)]
    layout: Vec<crate::arg_layout::LayoutStep>,
    name: String,
    params: Vec<CParamEmission>,
    /// Decode and argument-trace statements (see [`crate::arg_trace`]).
    decode: Vec<String>,
    after: Vec<String>,
    return_type: String,
    return_type_present: bool,
    result_name: String,
    marks_target: bool,
}

/// Template-level factory context: serialised into the Tera template so the
/// harness emits owner construction + factory call + null-guarded method call.
#[derive(Debug, Serialize)]
struct CppTemplateFactoryContext {
    /// The factory arguments' decode layout (see [`crate::arg_layout`]).
    #[serde(skip)]
    layout: Vec<crate::arg_layout::LayoutStep>,
    /// Qualified owner type for an instance-method factory (e.g.,
    /// `"tinyxml2::XMLDocument"`); empty string for a free-function factory.
    owner_type: String,
    owner_method_is_static: bool,
    method: String,
    params: Vec<CParamEmission>,
    /// Decode and argument-trace statements (see [`crate::arg_trace`]).
    decode: Vec<String>,
    receiver_is_pointer: bool,
}

/// Detect adjacent (raw-buffer, length) pairs in a C++ parameter list and
/// emit a Data+Size view, falling back to the per-parameter C++ decoder
/// for everything else. Mirrors the C-side `build_param_decoders` so a
/// `void Parse(const char *xml, size_t nBytes)`-shaped C++ API stops
/// receiving random mismatched length+heap-string and starts receiving
/// coherent libFuzzer input.
fn build_cpp_param_decoders(
    params: &[CppParameter],
    registry: &TypeRegistry,
    handle_lifecycle: &[crate::c_decoders::CHandleLifecycle],
    limits: &CppDecoderLimits,
    // Force-fuzz mode (`auto --force`). When true, a parameter the type-directed
    // decoders reject gets a best-effort compiling driver instead of failing the
    // whole target. Default-path callers pass `false` (emission unchanged).
    force: bool,
    // The target is a user-defined-literal operator (`operator"" _x`). By
    // [lex.ext], its `(charT const *, size_t)` parameters are the literal and its
    // EXACT length — intrinsically paired. The length must therefore be bound to
    // the buffer's own char count (`Size`), never an independent fuzzed value: a
    // decoupled `n` up to 65536 made `std::string(s, n)` read past a `Size`-byte
    // buffer (nlohmann `operator"" _json_pointer` → ASan heap-overflow FALSE
    // POSITIVE). Default-path callers pass `false`.
    literal_operator: bool,
) -> Result<Vec<CParamEmission>, HarnessGenError> {
    // Strip leading declaration-specifier / attribute / decoration-macro noise
    // from every parameter type up front (`__restrict`, `HB_UNUSED`, etc.) so the
    // generated `<type> arg` declarations and decoders never see it.
    let params: Vec<CppParameter> = params
        .iter()
        .enumerate()
        .map(|(i, p)| CppParameter {
            // Synthesize a name for an unnamed parameter so the decoder never
            // emits `Type ;` / `memset(&, 0, sizeof )` with empty operands.
            name: crate::c_decoders::sanitize_or_synthesize_param_name(&p.name, i),
            cpp_type: crate::c_decoders::strip_type_decoration(&p.cpp_type),
        })
        .collect();
    let params = &params[..];
    let mut out = Vec::with_capacity(params.len());
    let mut i = 0;
    let mut pair_consumed = false;
    while i < params.len() {
        // User-defined-literal string operator: `operator"" _x(charT const *s,
        // size_t n)`. By [lex.ext] `n` is the literal's exact length, so it must
        // track the buffer — bind `s` via the standalone char decoder (a
        // NUL-terminated `Size`-byte copy, safe for both `string(s, n)` and a
        // C-string `string(s)`) and `n = Size`. Without this, `n` was an
        // independent fuzzed length that overran `s` (heap-overflow FALSE POSITIVE).
        if literal_operator
            && i == 0
            && params.len() == 2
            && is_cpp_char_pointer_param(&params[0].cpp_type)
            && is_length_cpp_param(&params[1].cpp_type)
        {
            if let Ok(s_emission) = select_cpp_decoder_with_registry_limited(
                &params[0].cpp_type,
                &params[0].name,
                registry,
                limits,
            ) {
                out.push(s_emission);
                let len_type = params[1]
                    .cpp_type
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                out.push(CParamEmission {
                    support: None,
                    decl: format!(
                        "{len_type} {} = ({len_type})({} ? Size : 0)",
                        params[1].name, params[0].name
                    ),
                    arg: params[1].name.clone(),
                    c_type: len_type,
                    free: None,
                });
                break;
            }
        }
        if i + 1 < params.len()
            && is_output_buffer_cpp_param(&params[i].cpp_type, registry)
            && is_length_pointer_cpp_param(&params[i + 1].cpp_type)
            && looks_like_cpp_output_capacity_pair(&params[i], &params[i + 1])
        {
            let (buf_decl, len_decl) = pair_cpp_output_buffer_length(&params[i], &params[i + 1]);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            continue;
        }
        if i + 1 < params.len()
            && is_output_buffer_cpp_param(&params[i].cpp_type, registry)
            && (is_length_cpp_param(&params[i + 1].cpp_type)
                || crate::c_generate::registry_resolves_to_length(
                    &params[i + 1].cpp_type,
                    registry,
                ))
            && looks_like_cpp_output_capacity_pair(&params[i], &params[i + 1])
        {
            let (buf_decl, len_decl) = pair_cpp_output_buffer_capacity(&params[i], &params[i + 1]);
            out.push(buf_decl);
            out.push(len_decl);
            i += 2;
            continue;
        }
        if !pair_consumed
            && i + 1 < params.len()
            // Both sides resolve through the type registry, as in the C lane: a
            // typedef'd byte pointer (`const u8_t *`, `const BYTE *`) or length
            // (`UINT`, `DWORD`) that failed to pair left the buffer a whole-input
            // copy and the length an independent fuzzed value that overran it.
            && (is_raw_buffer_cpp_param_resolved(&params[i].cpp_type, registry)
                || crate::c_generate::registry_resolves_to_byte_pointer(
                    &params[i].cpp_type,
                    registry,
                ))
            && (is_length_cpp_param(&params[i + 1].cpp_type)
                || crate::c_generate::registry_resolves_to_length(
                    &params[i + 1].cpp_type,
                    registry,
                ))
            // Require NAME evidence on the LENGTH before binding (buffer, Size),
            // mirroring the C lane: `pugi::xml_document::load_file(const char
            // *path_, unsigned int options)` was mis-read as a (buffer, length)
            // pair — binding `path_` to the raw, non-NUL-terminated Data span (a
            // file path the parser then ran off the end of: a heap-buffer-overflow
            // FALSE POSITIVE). A buffer-shaped pointer name is not evidence either:
            // `(src, offset, size)` bound `offset` to Size, so every read started
            // one past the end of the input.
            && crate::c_generate::looks_like_count_name(&params[i + 1].name)
        {
            let buf = &params[i];
            let len = &params[i + 1];
            let buf_type = normalize_cpp_pointer(&buf.cpp_type);
            let len_type = len
                .cpp_type
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let const_buffer = is_const_cpp_pointer_type(&buf_type);
            // A pointer typedef (`LPCBYTE`, `PBYTE`) hides whether the bytes are
            // const. Its buffer is always a heap copy whose length is the copy's
            // size, which is right for both; the `(void *)` casts let the copy
            // and the free compile when the pointee is const.
            let hidden_pointer = cpp_pointer_base(&buf_type).is_none();
            let buf_ref = if hidden_pointer {
                format!("(void *){}", buf.name)
            } else {
                buf.name.clone()
            };
            let buf_decl = if const_buffer {
                format!("{buf_type} {} = ({buf_type})Data", buf.name)
            } else {
                format!(
                    "size_t _bhf_cap_{} = Size <= (1024 * 1024) ? (size_t)Size : (1024 * 1024); \
                     {buf_type} {} = ({buf_type})malloc(_bhf_cap_{} ? _bhf_cap_{} : 1); \
                     if ({} && _bhf_cap_{}) memcpy({buf_ref}, Data, _bhf_cap_{})",
                    buf.name, buf.name, buf.name, buf.name, buf.name, buf.name, buf.name
                )
            };
            let len_decl = if const_buffer {
                format!("{len_type} {} = ({len_type})Size", len.name)
            } else {
                format!(
                    "{len_type} {} = ({len_type})({} ? _bhf_cap_{} : 0)",
                    len.name, buf.name, buf.name
                )
            };
            out.push(CParamEmission {
                support: None,
                decl: buf_decl,
                arg: buf.name.clone(),
                c_type: buf_type.clone(),
                free: (!const_buffer).then(|| format!("free({buf_ref})")),
            });
            out.push(CParamEmission {
                support: None,
                decl: len_decl,
                arg: len.name.clone(),
                c_type: len_type,
                free: None,
            });
            i += 2;
            pair_consumed = true;
            continue;
        }
        let emission = match select_cpp_decoder_with_registry_limited(
            &params[i].cpp_type,
            &params[i].name,
            registry,
            limits,
        ) {
            Ok(emission) => emission,
            // The C++ decoder bails on an opaque-handle pointer (an opaque
            // `void`-typedef the fuzzer can't synthesize). If the CLI discovered a
            // FREE-function lifecycle for it (libde265's `de265_decoder_context *`
            // via `de265_new_decoder`/`de265_free_decoder`), construct it through
            // that lifecycle instead of failing. Fall back to the original error
            // if no lifecycle applies, so a genuinely un-drivable param still fails.
            Err(cpp_err) => {
                let via_lifecycle = (!handle_lifecycle.is_empty())
                    .then(|| {
                        crate::c_decoders::select_c_decoder_with_lifecycle_cpp(
                            &params[i].cpp_type,
                            &params[i].name,
                            registry,
                            handle_lifecycle,
                        )
                        .ok()
                    })
                    .flatten();
                match via_lifecycle {
                    Some(emission) => emission,
                    None if force => crate::c_decoders::best_effort_param_emission(
                        &params[i].cpp_type,
                        &params[i].name,
                    ),
                    None => {
                        return Err(HarnessGenError::UnsupportedParamType(format!(
                            "C++ parameter '{}' of type '{}' has no byte-buffer decoder \
                     (auto-harness drives scalar, string, and visible aggregate params): {cpp_err}",
                            params[i].name, params[i].cpp_type
                        )));
                    }
                }
            }
        };
        out.push(emission);
        i += 1;
    }
    Ok(out)
}

/// Collapse whitespace and separate a pointer declarator from its base type
/// (`u8_t*` -> `u8_t *`, `char**` -> `char **`), so the pointer-shape checks
/// below see one spelling whatever the parser produced.
fn normalize_cpp_pointer(c_type: &str) -> String {
    let mut spaced = String::with_capacity(c_type.len() + 2);
    let mut prev = ' ';
    for ch in c_type.chars() {
        if ch == '*' && prev != '*' && !prev.is_whitespace() {
            spaced.push(' ');
        }
        spaced.push(ch);
        prev = ch;
    }
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn is_raw_buffer_cpp_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    let without_const = normalized.trim_start_matches("const ").trim();
    cpp_pointer_base(without_const).is_some_and(is_cpp_byte_buffer_base)
}

/// [`is_raw_buffer_cpp_param`], also accepting a pointer whose element type is a
/// typedef (or typedef chain) of a byte scalar (`const u8_t *`, `const BYTE *`).
/// Only an explicit `T *` spelling qualifies: a pointer typedef hides its
/// constness, and the emitted copy-in for a writable buffer must not be applied
/// to a `const` pointee.
fn is_raw_buffer_cpp_param_resolved(cpp_type: &str, registry: &TypeRegistry) -> bool {
    if is_raw_buffer_cpp_param(cpp_type) {
        return true;
    }
    let normalized = normalize_cpp_pointer(cpp_type);
    let without_const = normalized.trim_start_matches("const ").trim();
    cpp_pointer_base(without_const)
        .is_some_and(|base| registry_resolves_to_byte_scalar(base, registry))
}

fn registry_resolves_to_byte_scalar(base: &str, registry: &TypeRegistry) -> bool {
    let base = base
        .split_whitespace()
        .filter(|token| *token != "const" && *token != "volatile")
        .collect::<Vec<_>>()
        .join(" ");
    matches!(
        registry.resolve(&base),
        type_model::TypeShape::Scalar(type_model::ScalarKind::U8 | type_model::ScalarKind::I8)
    )
}

/// Whether a target name is a user-defined-literal operator (`operator"" _x` /
/// `operator""_x`). The spelling varies by dialect (a space after `""` before the
/// suffix in C++11, none in C++17), so normalize whitespace before matching.
fn is_cpp_literal_operator(name: &str) -> bool {
    name.split_whitespace()
        .collect::<String>()
        .contains("operator\"\"")
}

/// A pointer to any character element — the first parameter of a user-defined
/// string-literal operator. Broader than [`is_raw_buffer_cpp_param`]: it also
/// accepts the wide/Unicode literal element types (`char8_t`/`char16_t`/
/// `char32_t`/`wchar_t`) that a UDL literal can carry but that are not byte
/// buffers for the generic (buffer, length) pairing.
fn is_cpp_char_pointer_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    let without_const = normalized.trim_start_matches("const ").trim();
    cpp_pointer_base(without_const).is_some_and(|base| {
        matches!(
            base,
            "char"
                | "unsigned char"
                | "signed char"
                | "char8_t"
                | "std::char8_t"
                | "char16_t"
                | "std::char16_t"
                | "char32_t"
                | "std::char32_t"
                | "wchar_t"
                | "uint8_t"
                | "std::uint8_t"
                | "int8_t"
                | "std::byte"
        )
    })
}

fn is_output_buffer_cpp_param(cpp_type: &str, registry: &TypeRegistry) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    if is_const_cpp_pointer_type(&normalized) {
        return false;
    }
    cpp_pointer_base(&normalized).is_some_and(|base| {
        is_cpp_byte_buffer_base(base) || registry_resolves_to_byte_scalar(base, registry)
    })
}

fn cpp_pointer_base(cpp_type: &str) -> Option<&str> {
    cpp_type
        .trim()
        .strip_suffix(" *")
        .map(str::trim)
        .filter(|base| !base.contains('*'))
}

fn is_const_cpp_pointer_type(cpp_type: &str) -> bool {
    cpp_pointer_base(cpp_type)
        .is_some_and(|base| base.split_whitespace().any(|token| token == "const"))
}

fn is_cpp_byte_buffer_base(base: &str) -> bool {
    matches!(
        base,
        "char" | "uint8_t" | "std::uint8_t" | "std::byte" | "unsigned char" | "void" | "int8_t"
    )
}

fn is_length_cpp_param(cpp_type: &str) -> bool {
    let normalized = cpp_type.split_whitespace().collect::<Vec<_>>().join(" ");
    let canonical = normalized.trim_start_matches("const ").trim();
    is_cpp_length_scalar_base(canonical)
}

fn is_length_pointer_cpp_param(cpp_type: &str) -> bool {
    let normalized = normalize_cpp_pointer(cpp_type);
    if is_const_cpp_pointer_type(&normalized) {
        return false;
    }
    cpp_pointer_base(&normalized).is_some_and(is_cpp_length_scalar_base)
}

fn is_cpp_length_scalar_base(base: &str) -> bool {
    matches!(
        base,
        "size_t"
            | "std::size_t"
            | "ssize_t"
            | "int"
            | "unsigned"
            | "unsigned int"
            | "long"
            | "unsigned long"
    )
}

fn pair_cpp_output_buffer_length(
    buffer: &CppParameter,
    length: &CppParameter,
) -> (CParamEmission, CParamEmission) {
    let buf_type = normalize_cpp_pointer(&buffer.cpp_type);
    let len_type = normalize_cpp_pointer(&length.cpp_type);
    let len_base = cpp_pointer_base(&len_type)
        .expect("caller checked length pointer")
        .to_owned();
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let cap_name = format!("_bhf_cap_{buf_name}");
    let len_storage = format!("_bhf_out_{len_name}");

    let buf_decl = format!(
        "size_t {cap_name} = Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536); \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1)"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_decl = format!(
        "{len_base} {len_storage} = ({len_base})({buf_name} ? {cap_name} : 0); {len_base} *{len_name} = &{len_storage}"
    );
    let len_emission = CParamEmission {
        support: None,
        decl: len_decl,
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

fn pair_cpp_output_buffer_capacity(
    buffer: &CppParameter,
    length: &CppParameter,
) -> (CParamEmission, CParamEmission) {
    let buf_type = normalize_cpp_pointer(&buffer.cpp_type);
    let len_type = length
        .cpp_type
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let buf_name = &buffer.name;
    let len_name = &length.name;
    let cap_name = format!("_bhf_cap_{buf_name}");

    let buf_decl = format!(
        "size_t {cap_name} = Size < (1024 * 1024) ? Size + 65536 : (1024 * 1024 + 65536); \
         {buf_type} {buf_name} = ({buf_type})malloc({cap_name} ? {cap_name} : 1)"
    );
    let buf_emission = CParamEmission {
        support: None,
        decl: buf_decl,
        arg: buf_name.to_owned(),
        c_type: buf_type,
        free: Some(format!("free({buf_name})")),
    };
    let len_decl = format!("{len_type} {len_name} = ({len_type})({buf_name} ? {cap_name} : 0)");
    let len_emission = CParamEmission {
        support: None,
        decl: len_decl,
        arg: len_name.to_owned(),
        c_type: len_type,
        free: None,
    };
    (buf_emission, len_emission)
}

/// An output buffer followed by its capacity (by value or by pointer). As for
/// an input length, the capacity must be count-shaped by name: an output-shaped
/// buffer name says nothing about the integer after it, and binding `offset`
/// in `put_at(u8_t *dst, unsigned offset, unsigned n)` or `flags` in
/// `encode(u8_t *out, int flags)` to the capacity started every write at the
/// end of the allocation.
fn looks_like_cpp_output_capacity_pair(buffer: &CppParameter, length: &CppParameter) -> bool {
    crate::c_generate::looks_like_count_name(&length.name)
        && (looks_cpp_outputish(&buffer.name) || looks_cpp_outputish(&length.name))
}

fn looks_cpp_outputish(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("out")
        || lower.contains("output")
        || lower.contains("dest")
        || lower.contains("dst")
}

fn build_cpp_context<'a>(
    args: &'a GenerateCppDirectArgs,
    handle_lifecycle: &'a [crate::c_decoders::CHandleLifecycle],
) -> Result<CppTemplateContext, HarnessGenError> {
    build_cpp_context_common(CppContextInput {
        harness_id: &args.harness_id,
        source_path: &args.source_path,
        target: &args.target,
        params: &args.params,
        return_type: &args.return_type,
        target_includes: &args.target_includes,
        target_includes_dirs: &args.target_includes_dirs,
        target_sources: &args.target_sources,
        compile_flags: &args.compile_flags,
        c_runtime_include: &args.c_runtime_include,
        using_namespaces: &args.using_namespaces,
        result_cleanup: args.result_cleanup.as_deref(),
        constructor_params: &args.constructor_params,
        type_defs: &args.type_defs,
        default_constructible_classes: &args.default_constructible_classes,
        parameter_constructions: &args.parameter_constructions,
        receiver_class_override: args.receiver_class_override.as_deref(),
        lifecycle_steps: Vec::new(),
        protocol_steps: Vec::new(),
        handle_lifecycle,
        factory_plan: args.factory_plan.as_ref(),
        decoder_limits: args.decoder_limits,
        force: args.force,
    })
}

fn build_cpp_sequence_context(
    args: &GenerateCppSequenceArgs,
) -> Result<CppTemplateContext, HarnessGenError> {
    let registry = TypeRegistry::from_defs(args.type_defs.iter())
        .with_cpp_lookup_scopes(cpp_lexical_lookup_scopes(&args.target))
        .with_default_constructible_classes(args.default_constructible_classes.iter().cloned());
    let lifecycle_steps = build_lifecycle_step_emissions(
        &args.lifecycle_steps,
        &args.target.qualifier_path,
        &registry,
        args.decoder_limits,
    )?;
    let protocol_steps = build_cpp_protocol_emissions(
        &args.protocol_steps,
        &args.target.qualifier_path,
        &registry,
        args.decoder_limits,
    )?;
    build_cpp_context_common(CppContextInput {
        harness_id: &args.harness_id,
        source_path: &args.source_path,
        target: &args.target,
        params: &args.params,
        return_type: &args.return_type,
        target_includes: &args.target_includes,
        target_includes_dirs: &args.target_includes_dirs,
        target_sources: &args.target_sources,
        compile_flags: &args.compile_flags,
        c_runtime_include: &args.c_runtime_include,
        using_namespaces: &args.using_namespaces,
        result_cleanup: args.result_cleanup.as_deref(),
        constructor_params: &args.constructor_params,
        type_defs: &args.type_defs,
        default_constructible_classes: &args.default_constructible_classes,
        parameter_constructions: &args.parameter_constructions,
        receiver_class_override: args.receiver_class_override.as_deref(),
        lifecycle_steps,
        protocol_steps,
        handle_lifecycle: &[],
        factory_plan: args.factory_plan.as_ref(),
        decoder_limits: args.decoder_limits,
        // The C++ sequence path is not part of the force-fuzz direct flow.
        force: false,
    })
}

struct CppContextInput<'a> {
    harness_id: &'a str,
    source_path: &'a PathBuf,
    target: &'a CppFunction,
    params: &'a [CppParameter],
    return_type: &'a str,
    target_includes: &'a [String],
    target_includes_dirs: &'a [PathBuf],
    target_sources: &'a [PathBuf],
    compile_flags: &'a [String],
    c_runtime_include: &'a PathBuf,
    using_namespaces: &'a [String],
    result_cleanup: Option<&'a str>,
    constructor_params: &'a [CppParameter],
    type_defs: &'a [c_parser::CTypeDefs],
    default_constructible_classes: &'a [String],
    /// #99: construction recipes for opaque class parameters, keyed by canonical
    /// class spelling.
    parameter_constructions: &'a [(String, type_model::ClassConstruction)],
    receiver_class_override: Option<&'a str>,
    lifecycle_steps: Vec<CppLifecycleStepEmission>,
    protocol_steps: Vec<CppProtocolStepEmission>,
    /// Init/delete FREE-function lifecycles for opaque-handle parameters (an
    /// opaque `void`-typedef pointer the fuzzer can't synthesize, built via a
    /// `new`/`free` pair instead). Empty for harnesses without such a param.
    handle_lifecycle: &'a [crate::c_decoders::CHandleLifecycle],
    /// Factory plan for receiver construction (see `CppFactoryPlan`).
    factory_plan: Option<&'a CppFactoryPlan>,
    /// Configurable container/bitset/array decoder caps (§27.11).
    decoder_limits: CppDecoderLimits,
    /// Force-fuzz mode (`auto --force`). When true, a rejected parameter gets a
    /// best-effort compiling driver instead of failing the target. Default
    /// `false` (sequence path, unit tests) keeps the emission unchanged.
    force: bool,
}

/// C++ counterpart of `validate_c_build_inputs`: refuse untrusted
/// flags/paths/include dirs that could inject commands into the
/// generated Makefile recipe.
fn validate_cpp_build_inputs(input: &CppContextInput<'_>) -> Result<(), HarnessGenError> {
    use crate::build_safety::{
        ensure_all_build_paths_safe, ensure_all_compile_flags_safe, ensure_build_path_safe,
        make_path,
    };
    // Flags are recipe-only, so one that is safe once single-quoted is allowed.
    // Paths and include names may carry spaces, parentheses and apostrophes —
    // the Makefile double-quotes them, and an `#include "..."` literal holds
    // them — but no character that quoting cannot contain.
    ensure_all_compile_flags_safe(input.compile_flags.iter().map(String::as_str))?;
    ensure_all_build_paths_safe(
        "include name",
        input.target_includes.iter().map(String::as_str),
    )?;
    for dir in input.target_includes_dirs {
        ensure_build_path_safe("include dir", &make_path(dir))?;
    }
    for src in input.target_sources {
        ensure_build_path_safe("source path", &make_path(src))?;
    }
    ensure_build_path_safe("runtime include", &make_path(input.c_runtime_include))?;
    // Robustness gate (campaign: tinyobjloader): refuse to emit a harness whose
    // TARGET call would not compile because the parser handed us a non-identifier
    // leaf name or a parse-artifact return type (a mis-recovered `namespace X {`
    // arrives as a "function" named `X` with return type `namespace`). A clean
    // skip with an actionable reason beats an emitted `namespace R = X(...);`. Skip
    // the check for the libFuzzer passthrough entrypoint, which is emitted as a
    // definition rather than a call.
    if input.target.name != "LLVMFuzzerTestOneInput" {
        if !cpp_callable_member_name(&input.target.name) {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "C++ target '{}' is not a valid callable name (likely a parse-recovery \
                 artifact, e.g. a namespace mis-parsed as a function); skipping rather \
                 than emitting an uncompilable harness",
                input.target.name
            )));
        }
        if !cpp_return_type_emittable(input.return_type) {
            return Err(HarnessGenError::UnsupportedParamType(format!(
                "C++ target '{}' has a malformed return type '{}' (likely a parse-recovery \
                 artifact); skipping rather than emitting an uncompilable harness",
                input.target.name, input.return_type
            )));
        }
    }
    Ok(())
}

/// Strip leading declaration-specifier tokens that are illegal on a runtime-
/// initialized local result variable (`<ret> R = <call>;`).
///
/// `strip_type_decoration` already removes the bare keyword spellings
/// (`constexpr`/`consteval`/`static`/`inline`), but a macro that *expands* to such
/// a specifier reaches codegen unexpanded — the harness does not preprocess the
/// target header. utf8.h declares `utf8_constexpr14_impl int utf8cmp(...)` where
/// the macro expands to `constexpr` under C++14, so the literal token
/// `utf8_constexpr14_impl` survives into the return type and emitting
/// `utf8_constexpr14_impl int R = <runtime call>;` is rejected ("constexpr
/// variable 'R' must be initialized by a constant expression").
///
/// Drop a leading bare storage/constant-evaluation keyword, or a leading
/// identifier-shaped macro token whose lowercased form names a constant-evaluation
/// specifier (`constexpr`/`consteval`/`constinit`), but only while a real type
/// token still follows. cv-qualifiers (`const`/`volatile`) are deliberately NOT
/// stripped: `const char * R = call();` is legal and the `const` belongs to the
/// pointee, so removing it would corrupt the type (and reject assigning a
/// `const char *` return into a `char *` local).
fn strip_runtime_illegal_result_specifiers(return_type: &str) -> String {
    let toks: Vec<&str> = return_type.split_whitespace().collect();
    let mut i = 0;
    while i + 1 < toks.len() && is_runtime_illegal_result_specifier(toks[i]) {
        i += 1;
    }
    toks[i..].join(" ")
}

/// Whether a leading return-type token is a declaration specifier that is illegal
/// on (or, for a constexpr family, makes ill-formed) a runtime-initialized local.
/// See [`strip_runtime_illegal_result_specifiers`].
fn is_runtime_illegal_result_specifier(tok: &str) -> bool {
    if matches!(
        tok,
        "constexpr" | "consteval" | "constinit" | "static" | "inline"
    ) {
        return true;
    }
    // Match a macro that expands to a constant-evaluation specifier: an
    // identifier-shaped token whose lowercased form contains a constexpr/consteval/
    // constinit marker (utf8.h's `utf8_constexpr14_impl`, a `FOO_CONSTEXPR`, ...).
    // Restrict to identifier characters so punctuated type spellings (`char *`,
    // `std::string`) are never matched.
    if !tok.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let lower = tok.to_ascii_lowercase();
    ["constexpr", "consteval", "constinit"]
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Whether any token in `return_type` is an unexpanded all-caps decoration macro
/// — uppercase/digits/underscores, ≥3 chars, at least one letter, and CONTAINING
/// an underscore (the multi-segment shape of library macros: `TOML_CALLCONV`,
/// `FOO_EXTERNAL_LINKAGE`). Requiring the underscore keeps single-word real
/// all-caps typedefs (`DWORD`, `BYTE`, `HANDLE`, `BOOL`) — which compile fine as an
/// explicit result type — from being needlessly demoted to `auto`. Splits on the
/// punctuation that separates type tokens (`*`, `&`, `<`, `>`, `,`, `::`, `()`) so a
/// macro buried in a qualified/templated spelling is still caught.
fn return_type_has_macro_shaped_token(return_type: &str) -> bool {
    return_type
        .split(|c: char| {
            c.is_whitespace() || matches!(c, '*' | '&' | '<' | '>' | ',' | ':' | '(' | ')')
        })
        .any(|tok| {
            tok.len() >= 3
                && tok.contains('_')
                && tok.bytes().any(|b| b.is_ascii_uppercase())
                && tok
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
}

fn build_cpp_context_common(
    input: CppContextInput<'_>,
) -> Result<CppTemplateContext, HarnessGenError> {
    validate_cpp_build_inputs(&input)?;
    let expert_re2_parse = is_exact_re2_regexp_parse(&input);
    let input_references_type_defs = cpp_params_reference_type_defs(&input);
    let registry = TypeRegistry::from_defs(input.type_defs.iter())
        .with_cpp_lookup_scopes(cpp_lexical_lookup_scopes(input.target))
        .with_default_constructible_classes(input.default_constructible_classes.iter().cloned())
        .with_class_constructions(input.parameter_constructions.iter().cloned());
    // Template-function instantiation (#455 / §27.5): when the target carries a
    // resolved specialization, substitute its concrete type arguments into the
    // parameter / return types BEFORE decoding (so `const std::vector<T> &`
    // decodes as `const std::vector<int> &`) and remember the turbofish suffix
    // for the call. A non-template target has no args and is untouched.
    let template_subst: Vec<(String, String)> = input
        .target
        .template_type_params
        .iter()
        .cloned()
        .zip(input.target.instantiation_args.iter().cloned())
        .collect();
    let substituted_params_storage: Vec<CppParameter>;
    let effective_params: &[CppParameter] = if template_subst.is_empty() {
        input.params
    } else {
        substituted_params_storage = input
            .params
            .iter()
            .map(|p| CppParameter {
                name: p.name.clone(),
                cpp_type: substitute_template_type_params(&p.cpp_type, &template_subst),
            })
            .collect();
        &substituted_params_storage
    };
    let target_template_suffix = if input.target.instantiation_args.is_empty() {
        String::new()
    } else {
        format!("<{}>", input.target.instantiation_args.join(", "))
    };
    // A free-function byte-stream decoder is driven one byte at a time: the first
    // parameter is the untrusted byte (the loop variable), only params 2..N are
    // decoded/backed.
    let byte_stream = !input.target.api.is_method
        && input.constructor_params.is_empty()
        && input.lifecycle_steps.is_empty()
        && input.protocol_steps.is_empty()
        && is_cpp_byte_stream_decoder(&input.target.name, effective_params);
    let literal_operator = is_cpp_literal_operator(&input.target.name);
    let mut params = if byte_stream {
        build_cpp_param_decoders(
            effective_params.get(1..).unwrap_or(&[]),
            &registry,
            input.handle_lifecycle,
            &input.decoder_limits,
            input.force,
            literal_operator,
        )?
    } else {
        build_cpp_param_decoders(
            effective_params,
            &registry,
            input.handle_lifecycle,
            &input.decoder_limits,
            input.force,
            literal_operator,
        )?
    };
    apply_pugixml_buffer_cleanup(
        &input.target.qualifier_path,
        &input.target.name,
        effective_params,
        &mut params,
    );
    let constructor_params = build_constructor_param_emissions(
        input.constructor_params,
        &registry,
        &input.decoder_limits,
    )?;
    let factory = if let Some(plan) = input.factory_plan {
        let factory_params = build_constructor_param_emissions(
            &plan.factory_params,
            &registry,
            &input.decoder_limits,
        )?;
        let trace = cpp_trace_plan(
            "f",
            "receiver",
            crate::arg_trace::Role::Receiver,
            0,
            CppDecodeOrder::AfterOthers,
            &plan.factory_params,
            &factory_params,
            &registry,
        );
        Some(CppTemplateFactoryContext {
            layout: trace.layout,
            owner_type: plan.owner_type.clone().unwrap_or_default(),
            owner_method_is_static: plan.owner_method_is_static,
            method: plan.factory_method.clone(),
            params: factory_params,
            decode: trace.decode,
            receiver_is_pointer: plan.receiver_is_pointer,
        })
    } else {
        None
    };
    let build_context = split_cpp_build_context_flags(input.compile_flags);
    let lifecycle_steps = input.lifecycle_steps;
    let protocol_steps = input.protocol_steps;
    let factory_param_emissions: Vec<&CParamEmission> = factory
        .as_ref()
        .map(|f| f.params.iter().collect())
        .unwrap_or_default();
    let all_param_emissions = params
        .iter()
        .chain(constructor_params.iter())
        .chain(factory_param_emissions.iter().copied())
        .chain(lifecycle_steps.iter().flat_map(|step| step.params.iter()))
        .chain(protocol_steps.iter().flat_map(|step| step.params.iter()));
    let mut uses_array = false;
    let mut uses_bitset = false;
    let mut uses_chrono = false;
    let mut uses_deque = false;
    let mut uses_filesystem = false;
    let mut uses_forward_list = false;
    let mut uses_functional = false;
    let mut uses_list = false;
    let mut uses_map = false;
    let mut uses_memory = false;
    let mut uses_optional = false;
    let mut uses_set = false;
    let mut uses_span = false;
    let mut uses_tuple = false;
    let mut uses_unordered_map = false;
    let mut uses_unordered_set = false;
    let mut uses_utility = false;
    let mut uses_variant = false;
    for param in all_param_emissions {
        uses_array |= param.c_type.contains("std::array<");
        uses_bitset |= param.c_type.contains("std::bitset<");
        uses_chrono |= param.c_type.contains("std::chrono::");
        uses_deque |= param.c_type.contains("std::deque<");
        uses_filesystem |= param.c_type.contains("std::filesystem::");
        uses_forward_list |= param.c_type.contains("std::forward_list<");
        uses_functional |= param.c_type.contains("std::function<");
        uses_list |= param.c_type.contains("std::list<");
        uses_map |= param.c_type.contains("std::map<");
        uses_memory |=
            param.c_type.contains("std::unique_ptr<") || param.c_type.contains("std::shared_ptr<");
        uses_optional |= param.c_type.contains("std::optional<");
        uses_set |= param.c_type.contains("std::set<");
        uses_span |= param.c_type.contains("std::span<");
        uses_tuple |= param.c_type.contains("std::tuple<");
        uses_unordered_map |= param.c_type.contains("std::unordered_map<");
        uses_unordered_set |= param.c_type.contains("std::unordered_set<");
        uses_utility |= param.c_type.contains("std::pair<") || param.arg.contains("std::move(");
        uses_variant |=
            param.c_type.contains("std::variant<") || param.c_type.contains("std::monostate");
    }
    // Use the GNU dialect, not strict ISO. Real systems/embedded C++ codebases
    // (PX4, cFE, the kernel headers they pull in, zeek) pervasively use GNU
    // extensions -- `typeof`, statement expressions, `__attribute__`, anonymous
    // structs -- in headers the target transitively includes (PX4's drv_hrt.h
    // uses bare `typeof`). Strict `-std=c++NN` rejects those and the harness
    // fails to build through no fault of the parser under test; the GNU dialect
    // is a superset that accepts them and matches how these projects actually
    // compile. No downside for fuzzing the project's own translation units.
    // Default to gnu++20: modern C++ projects increasingly require C++20 features
    // (char8_t, concepts, three-way comparison — libheif, capnproto, ctre all
    // failed under gnu++17), and gnu++20 is a near-superset that still compiles
    // C++11/14/17 translation units, so it's the safer floor. `uses_span` is kept
    // for the <span> include but no longer gates the standard.
    let _ = uses_span;
    // The baked default is gnu++20; `--cxx-std` (published by `auto` as
    // BHF_CXX_STD) overrides it, and even without an override the Makefile's
    // CXX_STD is overridable at build time by the dialect ladder.
    // SECURITY: `cxx_standard` is spliced into `CXX_STD ?= <value>` and expanded into
    // the `-std=$(CXX_STD)` recipe that make runs through /bin/sh. BOTH sources here are
    // attacker-reachable from a scanned tree — `BHF_CXX_STD` carries the auto-loaded
    // `.bhf.toml`'s `cxx-std`, and `build_context.cxx_standard` carries a `-std=` recovered
    // from the tree's own `compile_commands.json`. A value that is not a bare dialect name
    // is dropped for the built-in default rather than trusted.
    let cxx_standard = std::env::var("BHF_CXX_STD")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .or_else(|| build_context.cxx_standard.clone())
        .filter(|s| crate::build_safety::is_cxx_standard_token(s))
        .unwrap_or_else(|| "gnu++20".to_owned());

    // Qualify unqualified std names in the result type too (the harness lacks
    // the target's `using std::map;` etc.): `R = obj.foo()` declared as
    // `map<string, Json>` -> "no template named 'map'". A template result type
    // (`T`) is first specialised to the chosen instantiation (#455 / §27.5) so
    // `T R = convert<int>(..)` becomes `int R = convert<int>(..)`.
    let substituted_return = if template_subst.is_empty() {
        input.return_type.trim().to_owned()
    } else {
        substitute_template_type_params(input.return_type.trim(), &template_subst)
    };
    let return_type =
        crate::cpp_decoders::qualify_std_type_names(&strip_runtime_illegal_result_specifiers(
            &crate::c_decoders::strip_type_decoration(substituted_return.trim()),
        ));
    // Robust fallback: if the cleaned return type STILL carries an unexpanded
    // decoration macro (e.g. an export/linkage/calling-convention macro the parser
    // didn't recognise — `TOML_EXTERNAL_LINKAGE`, `FOO_CALLCONV`), writing
    // `<ret> R = call();` won't compile because the header `#undef`s that token. We
    // can't preprocess the header, but `auto R = call();` deduces the real type and
    // always compiles when the call does. See [`return_type_has_macro_shaped_token`].
    let return_type = if return_type_has_macro_shaped_token(&return_type) {
        "auto".to_owned()
    } else {
        return_type
    };
    let return_type_present = !return_type.is_empty() && return_type != "void";

    let qualified_target_name = if input.target.qualifier_path.is_empty() {
        input.target.name.clone()
    } else {
        format!(
            "{}::{}",
            input.target.qualifier_path.join("::"),
            input.target.name
        )
    };
    // A receiver instance is needed only for an actual member function, and
    // its type is the full qualifier path (namespace(s) + (nested) class),
    // e.g. `Json::Value`, `acme::v2::XmlReader`. `is_method` is the
    // authoritative signal — inferring "is this a class" from the
    // capitalization of the last qualifier segment wrongly treats a free
    // function in a Capitalized namespace (jsoncpp's `Json::releaseStringValue`)
    // as a method of class `Json`, synthesising a bogus `Json _bhf_receiver`.
    let receiver_class = if input.target.api.is_method
        && !input.target.is_static
        && !input.target.qualifier_path.is_empty()
    {
        // #456: an abstract declaring class is replaced by a concrete subclass the
        // caller resolved, so the receiver is constructible and the virtual method
        // dispatches to the subclass's implementation.
        Some(
            input
                .receiver_class_override
                .map(str::to_owned)
                .unwrap_or_else(|| input.target.qualifier_path.join("::")),
        )
    } else {
        None
    };
    let pugi_retained_buffers = receiver_class.is_some()
        && params
            .iter()
            .chain(lifecycle_steps.iter().flat_map(|step| step.params.iter()))
            .chain(protocol_steps.iter().flat_map(|step| step.params.iter()))
            .any(|p| {
                p.free
                    .as_deref()
                    .is_some_and(|cleanup| cleanup.starts_with("_bhf_retained_buffers.push_back("))
            });
    let target_is_constructor = receiver_class.is_some() && input.target.api.is_constructor;
    let include_source_for_receiver = receiver_class.is_some()
        && input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path);
    let include_source_for_type_defs = input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path)
        && input_references_type_defs;
    // A same-file template instantiation needs the template's DEFINITION (its
    // body), not just a declaration — a `convert<int>(..)` call can only be
    // instantiated where the template body is visible, and the linked `.cpp`
    // never exports an `int convert(..)` symbol. So include the source `.cpp`
    // itself (and drop it from the separately-compiled sources), exactly like the
    // receiver case (#455 / §27.5). When the template lives in an included header
    // this is moot — `has_target_header` already suppresses the forward decl.
    let include_source_for_template = !input.target.instantiation_args.is_empty()
        && input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path);
    // A header-less `.cpp` free function whose signature carries a REFERENCE or an
    // STL container needs its exact declaration in scope: the synthesized forward
    // declaration renders the decode-friendly by-value type (`std::vector<uint8_t>`)
    // for a `const std::vector<unsigned char>&` parameter, and the two mangle
    // differently — the harness then fails to link with `undefined symbol`.
    // Including the source `.cpp` (and dropping it from the separately-linked
    // sources, below) brings the real signature into scope, so no forward
    // declaration is emitted and the call binds to the true definition.
    let include_source_for_reference_param = input.target_includes.is_empty()
        && is_cpp_implementation_file(input.source_path)
        && input
            .target
            .params
            .iter()
            .any(|param| param.cpp_type.contains('&') || param.cpp_type.contains("std::"));
    let include_source = include_source_for_receiver
        || include_source_for_type_defs
        || include_source_for_template
        || include_source_for_reference_param;
    let mut target_includes = input.target_includes.to_vec();
    let mut target_sources = input.target_sources.to_vec();
    if include_source {
        if let Some(file_name) = input.source_path.file_name().and_then(|name| name.to_str()) {
            target_includes.push(file_name.to_owned());
        }
        target_sources.retain(|source| source != input.source_path);
    }
    // Only a header that DECLARES the target suppresses the forward declaration.
    // `include_source` above pulls the defining `.cpp` in as an "include", which
    // does bring the declaration into scope, so it counts without a search.
    let has_target_header = include_source
        || target_header_declares(
            &target_includes,
            input.target_includes_dirs,
            input.source_path,
            &input.target.name,
        );
    let mut using_namespaces = input.using_namespaces.to_vec();
    if include_source {
        push_cpp_target_namespace(
            &mut using_namespaces,
            input.target,
            receiver_class.is_some(),
        );
    }
    // Dedup the `using namespace X;` directives, preserving first-seen order: the
    // input list plus the pushed target namespace can repeat the same namespace,
    // emitting duplicate `using namespace simdjson;` lines (harmless but noisy,
    // and a duplicate that imports the same name from two scopes can make a call
    // ambiguous). One per namespace.
    {
        let mut seen = std::collections::HashSet::new();
        using_namespaces.retain(|ns| seen.insert(ns.clone()));
    }
    let passthrough_libfuzzer_entrypoint = input.target.name == "LLVMFuzzerTestOneInput";
    let lifecycle_step_count = lifecycle_steps.len();
    // A byte-stream target's first parameter is each input byte in turn; the
    // decoded parameters start at index 1.
    // A method whose receiver is built from decoded arguments, or driven by a
    // lifecycle loop, decodes the target's whole-input parameters last, right
    // before the call, so they take only bytes nothing else read.
    let defer_target_input =
        factory.is_some() || (receiver_class.is_some() && !input.target.api.is_constructor);
    let params_trace = cpp_trace_plan(
        "p",
        "target",
        crate::arg_trace::Role::Param,
        usize::from(byte_stream),
        if defer_target_input {
            CppDecodeOrder::FirstDeferringInput
        } else {
            CppDecodeOrder::First
        },
        if byte_stream {
            effective_params.get(1..).unwrap_or(&[])
        } else {
            effective_params
        },
        &params,
        &registry,
    );
    let constructor_trace = cpp_trace_plan(
        "c",
        "receiver",
        crate::arg_trace::Role::Receiver,
        0,
        CppDecodeOrder::AfterOthers,
        input.constructor_params,
        &constructor_params,
        &registry,
    );
    // The receiver object, as the template builds it: from a factory when one
    // is planned, else by its constructor (unless the target IS the constructor,
    // whose arguments are the target's own).
    let receiver_trace = if let Some(factory) = &factory {
        let how = if factory.owner_type.is_empty() {
            format!("factory {}()", factory.method)
        } else {
            format!("factory {}::{}()", factory.owner_type, factory.method)
        };
        Some(crate::arg_trace::receiver_statement(
            &input.target.qualifier_path.join("::"),
            &how,
        ))
    } else {
        receiver_class
            .as_deref()
            .filter(|_| !target_is_constructor)
            .map(|class| {
                let how = if constructor_params.is_empty() {
                    "default constructor".to_owned()
                } else {
                    format!(
                        "constructor({} decoded argument(s))",
                        constructor_params.len()
                    )
                };
                crate::arg_trace::receiver_statement(class, &how)
            })
    };

    // The decode layout, in the order the template runs the decodes: the
    // target's cursor parameters, a receiver's factory or constructor
    // arguments, mined protocol steps, a lifecycle loop, then the target's
    // whole-input parameters.
    let arg_layout = {
        use crate::arg_layout::{ArgLayout, LayoutStep};
        if expert_re2_parse {
            ArgLayout::new("cpp", "custom", Vec::new()).without_static_decode(
                "the harness passes the whole input to the parser as one pattern",
            )
        } else {
            let mut steps = params_trace.layout.clone();
            if let Some(factory) = &factory {
                steps.extend(factory.layout.iter().cloned());
            } else if receiver_class.is_some() && !target_is_constructor {
                steps.extend(constructor_trace.layout.iter().cloned());
                for step in &protocol_steps {
                    steps.extend(step.layout.iter().cloned());
                }
                if !lifecycle_steps.is_empty() {
                    steps.push(LayoutStep::Opaque {
                        what: format!(
                            "the receiver's lifecycle loop, which calls up to {} method(s) \
                             chosen by input bytes",
                            lifecycle_steps.len()
                        ),
                    });
                }
            }
            steps.extend(params_trace.late_layout.iter().cloned());
            ArgLayout::new(
                "cpp",
                if byte_stream { "byte_stream" } else { "direct" },
                steps,
            )
        }
    };

    let cxx_compiler_family = build_context.compiler_family().make_value().to_owned();
    // `CXX = <compiler>` heads every recipe; one under a spaced directory is
    // double-quoted so it stays a single word.
    let context_cxx = build_context.compiler.as_deref().unwrap_or("clang++");
    let cxx_compiler =
        crate::build_safety::recipe_path(&crate::build_safety::make_path(Path::new(context_cxx)));
    let c_compiler = crate::build_safety::recipe_path(&crate::build_safety::make_path(Path::new(
        &crate::compiler_family::c_driver_for(context_cxx),
    )));
    Ok(CppTemplateContext {
        arg_layout,
        harness_id: input.harness_id.to_owned(),
        qualified_target_name,
        expert_re2_parse,
        target_template_suffix,
        target_name: input.target.name.clone(),
        forward_namespace: input.target.qualifier_path.join("::"),
        // Compose with the result-variable stripper: that one removes a macro
        // expanding to a constant-evaluation specifier (utf8.h's
        // `utf8_constexpr14_impl int`), this one an export/calling-convention
        // decoration (`JNIEXPORT jstring`). A forward declaration must survive
        // both, since it names types the harness alone has to resolve.
        forward_return_type: strip_declaration_decoration(
            &strip_runtime_illegal_result_specifiers(input.return_type),
        ),
        forward_param_types: effective_params
            .iter()
            .map(|parameter| parameter.cpp_type.clone())
            .collect(),
        target_includes,
        target_includes_dirs: crate::c_generate::recipe_paths(input.target_includes_dirs),
        target_sources: crate::c_generate::recipe_paths(&target_sources),
        compile_flags: cpp_compile_flags_with_stl_compat(
            build_context.compile_flags,
            cfg!(windows),
        ),
        link_flags: build_context.link_flags,
        build_context_provenance: build_context.provenance,
        build_context_confidence: build_context.confidence,
        build_context_recovery: build_context.recovery,
        build_context_dropped: build_context.dropped,
        cxx_compiler,
        c_compiler,
        cxx_compiler_family,
        c_runtime_include: crate::build_safety::recipe_path(&crate::build_safety::make_path(
            input.c_runtime_include,
        )),
        params,
        params_decode: params_trace.decode,
        params_late: params_trace.late,
        params_after: params_trace.after,
        pugi_retained_buffers,
        return_type: if return_type_present {
            return_type
        } else {
            "void".to_owned()
        },
        return_type_present,
        constructor_params,
        constructor_decode: constructor_trace.decode,
        receiver_trace,
        receiver_class,
        target_is_constructor,
        target_is_method: input.target.api.is_method,
        has_target_header,
        using_namespaces,
        uses_array,
        uses_bitset,
        uses_chrono,
        uses_deque,
        uses_filesystem,
        uses_forward_list,
        uses_functional,
        uses_list,
        uses_map,
        uses_memory,
        uses_optional,
        uses_set,
        uses_span,
        uses_tuple,
        uses_unordered_map,
        uses_unordered_set,
        uses_utility,
        uses_variant,
        cxx_standard,
        passthrough_libfuzzer_entrypoint,
        result_cleanup: input.result_cleanup.map(str::to_owned),
        lifecycle_steps,
        lifecycle_step_count,
        protocol_steps,
        byte_stream,
        factory,
    })
}

/// Deliberately narrow gate for RE2's public low-level parser contract. The
/// generic decoder consumes control bytes before the pattern, leaves the
/// class-nested ParseFlags spelling unqualified, and cannot infer Regexp's
/// intrusive `Decref()` ownership. This exact declaration/header shape is safe
/// to drive the same way as RE2's maintained callers and fuzz harnesses.
fn is_exact_re2_regexp_parse(input: &CppContextInput<'_>) -> bool {
    input.target.name == "Parse"
        && input.target.qualifier_path == ["re2", "Regexp"]
        && input.target.params.len() == 3
        && input.target_includes.iter().any(|header| {
            Path::new(header)
                .file_name()
                .is_some_and(|name| name == "regexp.h")
        })
}

/// A free-function byte-stream decoder: a `parse`/`decode`-named function whose
/// first parameter is a single untrusted byte scalar the driver feeds one byte at
/// a time (PX4 st24_decode/sumd_decode). Mirrors the C-side detection.
fn is_cpp_byte_stream_decoder(name: &str, params: &[CppParameter]) -> bool {
    let Some(first) = params.first() else {
        return false;
    };
    let t = first
        .cpp_type
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if t.contains('*') || t.contains('&') {
        return false;
    }
    let t = t.trim_start_matches("const ").trim();
    let is_byte = matches!(
        t,
        "uint8_t" | "int8_t" | "unsigned char" | "signed char" | "char" | "u8" | "std::uint8_t"
    );
    let lower = name.to_ascii_lowercase();
    let parser = [
        "parse",
        "decode",
        "consume",
        "feed",
        "push_byte",
        "rx",
        "scan",
    ]
    .iter()
    .any(|kw| lower.contains(kw));
    is_byte && parser
}

fn push_cpp_target_namespace(
    using_namespaces: &mut Vec<String>,
    target: &CppFunction,
    has_receiver_class: bool,
) {
    let namespace = if !target.api.namespace_path.is_empty() {
        target.api.namespace_path.join("::")
    } else if has_receiver_class {
        target
            .qualifier_path
            .split_last()
            .map(|(_, ns)| ns.join("::"))
            .unwrap_or_default()
    } else {
        target.qualifier_path.join("::")
    };
    if !namespace.is_empty() && !using_namespaces.iter().any(|ns| ns == &namespace) {
        using_namespaces.push(namespace);
    }
}

/// Where a C++ call's arguments are decoded relative to the harness's other
/// decoding (see [`crate::arg_trace::Group`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CppDecodeOrder {
    /// The target's own arguments, decoded first from a fresh cursor.
    First,
    /// The target's own arguments when a receiver's constructor or factory
    /// arguments (or a lifecycle loop) are decoded between them and the call:
    /// their whole-input arguments are decoded last, right before the call.
    FirstDeferringInput,
    /// A receiver's constructor or factory, or a protocol or lifecycle step,
    /// decoded after the target's own arguments.
    AfterOthers,
}

/// The argument-trace plan for a C++ call's parameter emissions (see
/// [`crate::arg_trace`]). `params` are the parameters as declared, so a trace
/// line names a parameter by its declared name even where the harness renamed
/// its local.
#[allow(clippy::too_many_arguments)]
fn cpp_trace_plan(
    prefix: &str,
    call: &str,
    role: crate::arg_trace::Role,
    index_base: usize,
    order: CppDecodeOrder,
    params: &[CppParameter],
    emissions: &[CParamEmission],
    registry: &TypeRegistry,
) -> crate::arg_trace::DecodePlan {
    let declared: Vec<crate::arg_trace::Declared> = params
        .iter()
        .enumerate()
        .map(|(index, param)| {
            crate::arg_trace::Declared::new(
                crate::c_decoders::sanitize_or_synthesize_param_name(&param.name, index),
                crate::c_decoders::strip_type_decoration(&param.cpp_type),
            )
        })
        .collect();
    crate::arg_trace::plan(
        &crate::arg_trace::Group {
            lang: crate::arg_trace::Lang::Cpp,
            prefix,
            call,
            role,
            index_base,
            // The C++ trace dispatches on the type at compile time; the
            // registry only classifies the parameters' decode layout.
            registry: Some(registry),
            defer_input: order == CppDecodeOrder::FirstDeferringInput,
            fresh_cursor: order != CppDecodeOrder::AfterOthers,
            sized_buffers: crate::buffer_len_dimension_enabled(),
        },
        emissions,
        &declared,
    )
}

fn build_constructor_param_emissions(
    params: &[CppParameter],
    registry: &TypeRegistry,
    limits: &CppDecoderLimits,
) -> Result<Vec<CParamEmission>, HarnessGenError> {
    let renamed_params = params
        .iter()
        .enumerate()
        .map(|(param_index, param)| CppParameter {
            name: constructor_param_name(param_index, &param.name),
            cpp_type: param.cpp_type.clone(),
        })
        .collect::<Vec<_>>();
    build_cpp_param_decoders(&renamed_params, registry, &[], limits, false, false)
}

struct CppBuildContextRender {
    compile_flags: Vec<String>,
    link_flags: Vec<String>,
    provenance: String,
    confidence: String,
    recovery: String,
    dropped: String,
    cxx_standard: Option<String>,
    compiler: Option<String>,
}

impl CppBuildContextRender {
    /// The family the Makefile falls back to when it cannot ask `$(CXX)`:
    /// GCC for a GCC-named build-context compiler (cross prefixes included),
    /// Clang otherwise.
    fn compiler_family(&self) -> crate::compiler_family::CompilerFamily {
        self.compiler
            .as_deref()
            .and_then(crate::compiler_family::family_from_name)
            .unwrap_or(crate::compiler_family::CompilerFamily::Clang)
    }
}

/// Escape a build flag for verbatim interpolation into a Makefile recipe. A flag
/// may legitimately carry a quoted string-macro value (`-DREVISION_ID="lib-1.2.3"`,
/// from CMake / compile_commands.json); written raw into `$(CXX) ... -DX="v" ...`,
/// the shell strips the inner quotes and the macro expands UNQUOTED — a bare token,
/// not a string literal — breaking compilation. Backslash-escaping the quotes makes
/// the shell pass them through literally so the macro stays a string.
pub(crate) fn escape_makefile_recipe_flag(flag: &str) -> String {
    // A flag that is unsafe BARE but safe single-quoted gets the quotes. A CMake
    // version-comparison define (`-DLLAMA_VERSIONS=>=3`, gpt4all;
    // `-D_LIBCPP_HARDENING_MODE=..._DEBUG>`, btop) is legitimate, and its `>`
    // would redirect if emitted bare — refusing it cost every target in those
    // projects. `validate_*` has already rejected anything no quoting can save.
    if let Some(quoted) = crate::build_safety::quoted_build_input(flag) {
        return quoted;
    }
    if flag.contains('"') {
        flag.replace('"', "\\\"")
    } else {
        flag.to_owned()
    }
}

fn split_cpp_build_context_flags(flags: &[String]) -> CppBuildContextRender {
    let mut compile_flags = Vec::new();
    let mut link_flags = Vec::new();
    let mut provenance = "none".to_owned();
    let mut confidence = "none".to_owned();
    let mut recovery = "none".to_owned();
    let mut dropped = "none".to_owned();
    let mut cxx_standard = None;
    let mut compiler = None;

    for flag in flags {
        if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_PROVENANCE_PREFIX) {
            provenance = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_CONFIDENCE_PREFIX) {
            confidence = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_RECOVERY_PREFIX) {
            recovery = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_DROPPED_PREFIX) {
            dropped = value.to_owned();
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_LDFLAG_PREFIX) {
            link_flags.push(escape_makefile_recipe_flag(value));
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_CXX_STANDARD_PREFIX) {
            // Validated again at the emission boundary: these pseudo-flags are built from
            // tree-controlled input, and `ensure_all_compile_flags_safe` only ever saw the
            // PREFIXED form, where the single-quote relaxation makes `c++17; id` look
            // acceptable. Stripping the prefix removes that protection.
            cxx_standard =
                Some(value.to_owned()).filter(|v| crate::build_safety::is_cxx_standard_token(v));
        } else if let Some(value) = flag.strip_prefix(BUILD_CONTEXT_COMPILER_PREFIX) {
            compiler = Some(value.to_owned()).filter(|v| crate::build_safety::is_compiler_token(v));
        } else {
            compile_flags.push(escape_makefile_recipe_flag(flag));
        }
    }

    CppBuildContextRender {
        compile_flags,
        link_flags,
        // Metadata lands in `NAME = <value>` assignments; a newline would end the
        // assignment and let the remainder parse as Makefile source.
        provenance: crate::build_safety::make_metadata_value(&provenance),
        confidence: crate::build_safety::make_metadata_value(&confidence),
        recovery: crate::build_safety::make_metadata_value(&recovery),
        dropped: crate::build_safety::make_metadata_value(&dropped),
        cxx_standard,
        compiler,
    }
}

fn build_lifecycle_step_emissions(
    steps: &[CppLifecycleStep],
    owner: &[String],
    registry: &TypeRegistry,
    limits: CppDecoderLimits,
) -> Result<Vec<CppLifecycleStepEmission>, HarnessGenError> {
    // Robustness gate (campaign: tinyobjloader): never emit a `receiver.<step>(...)`
    // call the parser handed us with a non-identifier name or a parse-artifact
    // return type (a mis-recovered `namespace detail_fp {` arrives as a "method"
    // named `detail_fp` with return type `namespace`). Drop such steps — re-indexed
    // contiguously so `_bhf_step{n}` names and the emitted switch cases stay dense —
    // rather than producing an un-compilable harness. The parser reconciliation
    // normally removes these upstream; this is the belt-and-suspenders net.
    let steps: Vec<&CppLifecycleStep> = steps
        .iter()
        .filter(|step| {
            cpp_callable_member_name(&step.name) && cpp_return_type_emittable(&step.return_type)
        })
        .collect();
    steps
        .iter()
        .enumerate()
        .map(|(step_index, step)| {
            let renamed_params = step
                .params
                .iter()
                .enumerate()
                .map(|(param_index, param)| CppParameter {
                    name: lifecycle_param_name(step_index, param_index, &param.name),
                    cpp_type: param.cpp_type.clone(),
                })
                .collect::<Vec<_>>();
            let mut params =
                build_cpp_param_decoders(&renamed_params, registry, &[], &limits, false, false)?;
            apply_pugixml_buffer_cleanup(owner, &step.name, &step.params, &mut params);
            let return_type = step.return_type.trim().to_owned();
            let return_type_present = !return_type.is_empty() && return_type != "void";
            let trace = cpp_trace_plan(
                &format!("l{step_index}_"),
                &step.name,
                crate::arg_trace::Role::Param,
                0,
                CppDecodeOrder::AfterOthers,
                &step.params,
                &params,
                registry,
            );
            Ok(CppLifecycleStepEmission {
                name: step.name.clone(),
                params,
                decode: trace.decode,
                after: trace.after,
                return_type: if return_type_present {
                    return_type
                } else {
                    "void".to_owned()
                },
                return_type_present,
                result_name: format!("_bhf_step{step_index}_result"),
            })
        })
        .collect()
}

fn build_cpp_protocol_emissions(
    steps: &[CppProtocolStep],
    owner: &[String],
    registry: &TypeRegistry,
    limits: CppDecoderLimits,
) -> Result<Vec<CppProtocolStepEmission>, HarnessGenError> {
    steps
        .iter()
        .enumerate()
        .map(|(step_index, observed)| {
            if observed.step.params.len() != observed.args.len()
                || !cpp_callable_member_name(&observed.step.name)
                || !cpp_return_type_emittable(&observed.step.return_type)
            {
                return Err(HarnessGenError::UnsupportedParamType(format!(
                    "invalid mined C++ protocol step '{}'",
                    observed.step.name
                )));
            }
            let renamed = observed
                .step
                .params
                .iter()
                .enumerate()
                .map(|(param_index, param)| CppParameter {
                    name: scoped_param_name(
                        "_bhf_protocol",
                        Some(step_index),
                        param_index,
                        &param.name,
                    ),
                    cpp_type: param.cpp_type.clone(),
                })
                .collect::<Vec<_>>();
            let mut params =
                build_cpp_param_decoders(&renamed, registry, &[], &limits, false, false)?;
            for ((emission, parameter), recipe) in params
                .iter_mut()
                .zip(&observed.step.params)
                .zip(&observed.args)
            {
                match recipe {
                    CppProtocolArg::Decode => {}
                    CppProtocolArg::InputData => {
                        let ty = crate::c_decoders::strip_type_decoration(&parameter.cpp_type);
                        if !ty.contains('*') || !ty.split_whitespace().any(|token| token == "const")
                        {
                            return Err(HarnessGenError::UnsupportedParamType(format!(
                                "mined C++ input-data argument '{}' is not a const pointer",
                                parameter.cpp_type
                            )));
                        }
                        emission.decl = "/* bound directly to the fuzz input */".to_owned();
                        emission.arg = format!("reinterpret_cast<{ty}>(Data)");
                        emission.free = None;
                    }
                    CppProtocolArg::InputSize => {
                        if !is_length_cpp_param(&parameter.cpp_type) {
                            return Err(HarnessGenError::UnsupportedParamType(format!(
                                "mined C++ input-size argument '{}' is not integral",
                                parameter.cpp_type
                            )));
                        }
                        let ty = crate::c_decoders::strip_type_decoration(&parameter.cpp_type);
                        emission.decl = "/* bound directly to the fuzz input size */".to_owned();
                        emission.arg = format!("static_cast<{ty}>(Size)");
                        emission.free = None;
                    }
                    CppProtocolArg::Literal(value) => {
                        if !safe_cpp_protocol_literal(value) {
                            return Err(HarnessGenError::UnsupportedParamType(format!(
                                "unsafe mined C++ protocol literal '{value}'"
                            )));
                        }
                        emission.decl = "/* expert-observed literal */".to_owned();
                        emission.arg = value.clone();
                        emission.free = None;
                    }
                }
            }
            apply_pugixml_buffer_cleanup(
                owner,
                &observed.step.name,
                &observed.step.params,
                &mut params,
            );
            let return_type = observed.step.return_type.trim().to_owned();
            let return_type_present = !return_type.is_empty() && return_type != "void";
            let trace = cpp_trace_plan(
                &format!("s{step_index}_"),
                &observed.step.name,
                crate::arg_trace::Role::Param,
                0,
                CppDecodeOrder::AfterOthers,
                &observed.step.params,
                &params,
                registry,
            );
            Ok(CppProtocolStepEmission {
                layout: trace.layout,
                name: observed.step.name.clone(),
                params,
                decode: trace.decode,
                after: trace.after,
                return_type: if return_type_present {
                    return_type
                } else {
                    "void".to_owned()
                },
                return_type_present,
                result_name: format!("_bhf_protocol{step_index}_result"),
                marks_target: observed.marks_target,
            })
        })
        .collect()
}

/// `load_buffer_inplace_own` takes ownership even on failure. The non-owning
/// variant retains views into the caller's buffer until the document is reset;
/// its cleanup is deferred until that reset at the end of the generated call.
fn apply_pugixml_buffer_cleanup(
    owner: &[String],
    method: &str,
    parameters: &[CppParameter],
    emissions: &mut [CParamEmission],
) {
    if owner.len() == 2
        && owner[0] == "pugi"
        && owner[1] == "xml_document"
        && parameters
            .first()
            .is_some_and(|p| p.cpp_type.replace(' ', "") == "void*")
    {
        if let Some(first) = emissions.first_mut() {
            if method == "load_buffer_inplace_own" {
                first.free = None;
            } else if method == "load_buffer_inplace" && first.free.is_some() {
                first.free = Some(format!("_bhf_retained_buffers.push_back({})", first.arg));
            }
        }
    }
}

fn safe_cpp_protocol_literal(value: &str) -> bool {
    let value = value.trim();
    if matches!(value, "true" | "false" | "nullptr" | "NULL") {
        return true;
    }
    if (value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\''))
    {
        return value.len() >= 2;
    }
    let number = value.trim_start_matches(['+', '-']);
    !number.is_empty()
        && number
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
        && number
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'x' | b'X'))
}

fn lifecycle_param_name(step_index: usize, param_index: usize, raw: &str) -> String {
    scoped_param_name("_bhf_step", Some(step_index), param_index, raw)
}

fn constructor_param_name(param_index: usize, raw: &str) -> String {
    scoped_param_name("_bhf_ctor", None, param_index, raw)
}

fn scoped_param_name(
    prefix: &str,
    step_index: Option<usize>,
    param_index: usize,
    raw: &str,
) -> String {
    let mut out = String::from("_bhf_step");
    if prefix != "_bhf_step" {
        out = prefix.to_owned();
    }
    if let Some(step_index) = step_index {
        out.push_str(&step_index.to_string());
    }
    out.push('_');
    let mut saw_any = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
            saw_any = true;
        } else {
            out.push('_');
        }
    }
    if !saw_any {
        out.push('p');
        out.push_str(&param_index.to_string());
    }
    out
}

/// Drop a leading export / calling-convention decoration macro from a return
/// type, so a forward declaration the harness emits names only types it can see.
///
/// `JNIEXPORT jstring` -> `jstring`, `MAGICK_EXPORT Image *` -> `Image *`. The
/// macro is defined by the project's own headers, which the harness does not
/// include; copying it verbatim turns a declaration into `unknown type name
/// 'JNIEXPORT'` plus a cascade of parse errors — errors the target never had.
///
/// Only a LEADING all-caps token followed by more type text is removed, and only
/// when the token is not itself a plausible type: `UINT32 f()` keeps its return
/// type, because there is nothing after it to be the real one.
fn strip_declaration_decoration(return_type: &str) -> String {
    let trimmed = return_type.trim();
    let Some((head, rest)) = trimmed.split_once(char::is_whitespace) else {
        return trimmed.to_owned();
    };
    let rest = rest.trim();
    // Both all-caps means we cannot tell which one is the type (`WINAPI DWORD`),
    // so nothing is stripped — the target keeps whatever it had.
    if rest.is_empty() || !is_all_caps_token(head) || is_all_caps_token(rest) {
        return trimmed.to_owned();
    }
    rest.to_owned()
}

/// An identifier of only uppercase letters, digits and underscores, with at least
/// one letter — the shape of a macro, not of a written-out type.
fn is_all_caps_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && text.chars().any(|ch| ch.is_ascii_uppercase())
}

/// Whether any header the harness will include actually declares `target_name`.
///
/// Resolved against the target's own include directories and the directory of the
/// source the target came from — the same places the compiler will look. A header
/// that cannot be read is treated as NOT declaring the target: emitting a
/// redundant forward declaration for a global free function is harmless (C++
/// allows an identical redeclaration), while omitting a needed one is a build
/// failure, so uncertainty resolves toward emitting.
fn target_header_declares(
    target_includes: &[String],
    include_dirs: &[PathBuf],
    source_path: &Path,
    target_name: &str,
) -> bool {
    if target_includes.is_empty() {
        return false;
    }
    let mut roots: Vec<PathBuf> = include_dirs.to_vec();
    if let Some(parent) = source_path.parent() {
        roots.push(parent.to_path_buf());
    }
    target_includes.iter().any(|include| {
        roots.iter().any(|root| {
            std::fs::read_to_string(root.join(include))
                .ok()
                .is_some_and(|text| declares_identifier(&text, target_name))
        })
    })
}

/// Crude but sufficient: the identifier appears at a word boundary followed by an
/// opening parenthesis, i.e. as a function declarator rather than inside another
/// name. A comment or string mentioning `foo(` also matches, which only costs a
/// suppressed forward declaration on a header that is very likely to declare it
/// anyway.
fn declares_identifier(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    text.match_indices(name).any(|(start, _)| {
        let end = start + name.len();
        let before_ok = start == 0 || {
            let ch = bytes[start - 1];
            !ch.is_ascii_alphanumeric() && ch != b'_' && ch != b':' && ch != b'.'
        };
        let after_ok = text[end..].trim_start().starts_with('(');
        before_ok && after_ok
    })
}

fn is_cpp_implementation_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension == "C"
                || matches!(
                    extension.to_ascii_lowercase().as_str(),
                    "cc" | "cpp" | "cxx"
                )
        })
}

fn cpp_params_reference_type_defs(input: &CppContextInput<'_>) -> bool {
    let mut names = Vec::new();
    for defs in input.type_defs {
        for name in defs
            .structs
            .iter()
            .map(|def| def.name.as_str())
            .chain(defs.enums.iter().map(|def| def.name.as_str()))
            .chain(defs.typedefs.iter().map(|def| def.name.as_str()))
        {
            names.push(name);
            // Namespace-preserving registries store `gov::Mode`, while a
            // parameter declared inside that namespace is commonly spelled
            // just `Mode`. This decision only controls whether the defining
            // implementation must be included, so the leaf match is safe and
            // avoids emitting an undeclared enum/class type.
            if let Some(leaf) = name.rsplit("::").next().filter(|leaf| *leaf != name) {
                names.push(leaf);
            }
        }
    }
    if names.is_empty() {
        return false;
    }

    input
        .params
        .iter()
        .chain(input.constructor_params.iter())
        .any(|param| cpp_type_mentions_any_name(&param.cpp_type, &names))
}

fn cpp_type_mentions_any_name(cpp_type: &str, names: &[&str]) -> bool {
    cpp_type
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| names.contains(&token))
}

/// Substitute template type-parameter names with their concrete instantiation
/// arguments in a type spelling (#455 / §27.5): `const std::vector<T> &` with
/// `T -> int` becomes `const std::vector<int> &`. Replacement is WHOLE-IDENTIFIER
/// (a `T` token is replaced, the `T` inside `Tree` is not), so it never corrupts a
/// surrounding type name. Punctuation, `<`, `>`, `*`, `&`, `::`, and whitespace are
/// preserved verbatim. `subst` is positionally aligned (`template_type_params`
/// zipped with `instantiation_args`); an empty list returns the input unchanged.
fn substitute_template_type_params(cpp_type: &str, subst: &[(String, String)]) -> String {
    if subst.is_empty() {
        return cpp_type.to_owned();
    }
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::with_capacity(cpp_type.len());
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        if token.is_empty() {
            return;
        }
        let replacement = subst
            .iter()
            .find(|(param, _)| param == token)
            .map(|(_, arg)| arg.as_str())
            .unwrap_or(token.as_str());
        out.push_str(replacement);
        token.clear();
    };
    for ch in cpp_type.chars() {
        if is_ident(ch) {
            token.push(ch);
        } else {
            flush(&mut token, &mut out);
            out.push(ch);
        }
    }
    flush(&mut token, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn stl_compat_define_added_on_windows_only() {
        let base = vec!["-DFOO".to_owned(), "-I/x".to_owned()];
        // Off Windows: flags are untouched.
        assert_eq!(cpp_compile_flags_with_stl_compat(base.clone(), false), base);
        // On Windows: the MSVC STL escape hatch is prepended.
        let win = cpp_compile_flags_with_stl_compat(base.clone(), true);
        assert_eq!(win[0], "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH");
        assert!(win.contains(&"-DFOO".to_owned()));
        // Idempotent: not duplicated if already present.
        let again = cpp_compile_flags_with_stl_compat(win.clone(), true);
        assert_eq!(
            again
                .iter()
                .filter(|f| f.as_str() == "-D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH")
                .count(),
            1
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("bhf-cppgen-{name}-{nonce}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn cppfunction(name: &str) -> CppFunction {
        CppFunction {
            name: name.to_owned(),
            line: 1,
            return_type: String::new(),
            params: Vec::new(),
            qualifier_path: Vec::new(),
            api: cpp_parser::CppApiMetadata::default(),
            ..Default::default()
        }
    }

    fn runtime_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap()
    }

    fn clangxx_compile_flags(prefix: &str) -> Option<Vec<String>> {
        if clangxx_probe(prefix, &[]) {
            return Some(Vec::new());
        }
        for dir in [
            "/usr/lib/gcc/x86_64-linux-gnu/14",
            "/usr/lib/gcc/x86_64-linux-gnu/13",
            "/usr/lib/gcc/x86_64-linux-gnu/12",
            "/usr/lib/gcc/x86_64-linux-gnu/11",
        ] {
            let flag = format!("--gcc-install-dir={dir}");
            if clangxx_probe(prefix, std::slice::from_ref(&flag)) {
                return Some(vec![flag]);
            }
        }
        None
    }

    fn clangxx_probe(prefix: &str, extra_flags: &[String]) -> bool {
        let dir = temp_dir(&format!("{prefix}-clangxx-probe"));
        let src = dir.join("p.cpp");
        let obj = dir.join("p.o");
        let wrote = fs::write(
            &src,
            "#include <cstdint>\n#include <cstddef>\nint f(const uint8_t *d, size_t n) { return d && n ? d[0] : 0; }\n",
        )
        .is_ok();
        let ok = wrote
            && Command::new("clang++")
                .args(extra_flags)
                .args(["-std=c++17", "-c"])
                .arg(&src)
                .arg("-o")
                .arg(&obj)
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);
        let _ = fs::remove_dir_all(&dir);
        ok
    }

    #[test]
    fn generate_cpp_direct_harness_emits_main_and_makefile() {
        let out = temp_dir("cpp-emit");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP001".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["demo.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("LLVMFuzzerTestOneInput"));
        assert!(
            main.contains("#if defined(_WIN32)\n#define BHF_PUBLISH_INPUT(data, size) ((void)0)")
                && main.contains("BHF_PUBLISH_INPUT(Data, Size);"),
            "Windows harnesses must omit the Linux-only weak runtrace hook:\n{main}"
        );
        // A forward declaration must precede the entrypoint definition so the
        // harness compiles under projects that promote -Wmissing-prototypes to an
        // error (harfbuzz's hb.hh does exactly this).
        assert!(
            main.contains("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *, size_t);"),
            "missing -Wmissing-prototypes forward declaration:\n{main}"
        );
        assert!(main.contains("std::string input"));
        assert!(main.contains("int R = demo::parse(input);"));
        // #408: the C++ driver must carry the same bhf coverage runtime +
        // persistent framed fork-server main the C driver has, so the engine
        // sees non-zero coverage on C++ amalgamations (was coverage_edges=0).
        assert!(
            main.contains("__sanitizer_cov_trace_pc_guard"),
            "C++ driver missing edge-coverage runtime:\n{main}"
        );
        assert!(
            main.contains("BHF_COV_SHM") && main.contains("BHF_FRAMED"),
            "C++ driver missing coverage SHM / framed fork-server main:\n{main}"
        );
        assert!(
            main.find("#include \"demo.h\"") < main.find("#undef getenv")
                && main.find("#undef getenv") < main.find("getenv(\"BHF_COV_SHM\")"),
            "target-header getenv redirects must be cleared before the coverage runtime:\n{main}"
        );
        // The sanitizer callbacks must have C linkage or name-mangling hides them
        // from the sanitizer runtime.
        assert!(
            main.contains("extern \"C\" {"),
            "C++ sanitizer runtime must be wrapped in extern \"C\":\n{main}"
        );

        let mk = fs::read_to_string(&result.makefile).unwrap();
        assert!(mk.contains("ifeq ($(origin CXX), default)"));
        assert!(mk.contains("CXX = clang++"));
        assert!(mk.contains("CXX_STD ?= gnu++20"));
        assert!(mk.contains("-Wno-reserved-user-defined-literal"));
        // #408: instrument with trace-pc-guard,trace-cmp (like the C makefile) and
        // do NOT link libFuzzer's own main on the default recipe — mixing it in
        // mis-drove the binary and fabricated empty-testcase findings.
        assert!(
            mk.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp"),
            "C++ default recipe missing coverage instrumentation:\n{mk}"
        );
        // The default recipe carries no libFuzzer; it is a separate opt-in target
        // (`make libfuzzer`) for external drivers, so `-fsanitize=fuzzer` appears
        // only in the dedicated LIBFUZZER_CXXFLAGS/main_libfuzzer target.
        let cxxflags_line = mk
            .lines()
            .find(|l| l.trim_start().starts_with("CXXFLAGS ?="))
            .unwrap_or("");
        assert!(
            !cxxflags_line.contains("fuzzer"),
            "C++ default recipe must not link libFuzzer's main:\n{mk}"
        );
        assert!(
            mk.contains("libfuzzer: main_libfuzzer")
                && mk.contains("-fsanitize=fuzzer,address,undefined"),
            "C++ opt-in libFuzzer target must exist:\n{mk}"
        );
        // The FP-prone UBSan checks are subtracted so callback/vptr-heavy C++
        // libraries fuzz instead of aborting on every input under halt_on_error.
        assert!(
            mk.contains("-fsanitize=address,undefined -fno-sanitize=function,vptr,alignment"),
            "C++ default recipe must subtract FP-prone UBSan checks:\n{mk}"
        );
    }

    #[test]
    fn static_member_uses_qualified_call_without_receiver() {
        let out = temp_dir("cpp-static-member");
        let mut target = cppfunction("Parse");
        target.qualifier_path = vec!["demo".to_owned(), "Regexp".to_owned()];
        target.api.namespace_path = vec!["demo".to_owned()];
        target.api.class_name = Some("Regexp".to_owned());
        target.api.is_method = true;
        target.is_static = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STATIC".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/parse.cc"),
            target,
            params: vec![CppParameter {
                name: "text".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["regexp.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/parse.cc")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("demo::Regexp::Parse(text)"), "{main}");
        assert!(!main.contains("_bhf_receiver"), "{main}");
        assert!(
            !main.contains("namespace demo::Regexp"),
            "a static method must not be redeclared as a namespace free function:\n{main}"
        );
    }

    #[test]
    fn re2_parse_uses_whole_input_flags_status_and_intrusive_cleanup() {
        let out = temp_dir("cpp-re2-parse");
        let include = out.join("include");
        fs::create_dir_all(include.join("re2")).unwrap();
        fs::write(
            include.join("re2/regexp.h"),
            r#"
                #include <string_view>
                namespace absl { using string_view = std::string_view; }
                namespace re2 {
                class RegexpStatus {};
                class Regexp {
                 public:
                  enum ParseFlags { LikePerl = 1 };
                  static Regexp *Parse(absl::string_view, ParseFlags, RegexpStatus *);
                  void Decref();
                };
                }
            "#,
        )
        .unwrap();
        let runtime = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../c_runtime")
            .canonicalize()
            .unwrap();
        let mut target = cppfunction("Parse");
        target.qualifier_path = vec!["re2".to_owned(), "Regexp".to_owned()];
        target.api.namespace_path = vec!["re2".to_owned()];
        target.api.class_name = Some("Regexp".to_owned());
        target.api.is_method = true;
        target.is_static = true;
        target.params = vec![
            cpp_parser::CppParamDescriptor {
                name: "pattern".to_owned(),
                cpp_type: "absl::string_view".to_owned(),
                has_default: false,
            },
            cpp_parser::CppParamDescriptor {
                name: "flags".to_owned(),
                cpp_type: "ParseFlags".to_owned(),
                has_default: false,
            },
            cpp_parser::CppParamDescriptor {
                name: "status".to_owned(),
                cpp_type: "RegexpStatus *".to_owned(),
                has_default: false,
            },
        ];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-RE2".to_owned(),
            output_dir: out.join("harness"),
            source_path: out.join("parse.cc"),
            target,
            params: vec![
                CppParameter {
                    name: "pattern".to_owned(),
                    cpp_type: "absl::string_view".to_owned(),
                },
                CppParameter {
                    name: "flags".to_owned(),
                    cpp_type: "int".to_owned(),
                },
                CppParameter {
                    name: "status".to_owned(),
                    cpp_type: "int *".to_owned(),
                },
            ],
            return_type: "re2::Regexp *".to_owned(),
            target_includes: vec!["re2/regexp.h".to_owned()],
            target_includes_dirs: vec![include.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("reinterpret_cast<const char *>(Data), Size"),
            "{main}"
        );
        assert!(main.contains("re2::Regexp::LikePerl"), "{main}");
        assert!(main.contains("re2::RegexpStatus _bhf_status"), "{main}");
        assert!(main.contains("if (R) R->Decref()"), "{main}");
        assert!(!main.contains("bhf_cursor Cur ="), "{main}");

        if let Some(cxx_flags) = clangxx_compile_flags("cpp-re2-parse") {
            let output = Command::new("clang++")
                .args(&cxx_flags)
                .arg("-std=c++17")
                .arg("-I")
                .arg(include)
                .arg("-I")
                .arg(runtime)
                .arg("-c")
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(out.join("re2-harness.o"))
                .output()
                .expect("spawn clang++");
            assert!(
                output.status.success(),
                "clang++ failed:\n{}\n{main}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn user_defined_literal_operator_binds_length_to_buffer_size() {
        // nlohmann `operator"" _json_pointer(const char8_t *s, std::size_t n)`: by
        // [lex.ext] `n` is the literal's exact length, so it MUST bind to the
        // buffer's own char count (`Size`), not an independent fuzzed length — a
        // decoupled `n` up to 65536 made `std::string(s, n)` read past the
        // `Size`-byte `s` (ASan heap-buffer-overflow FALSE POSITIVE).
        let out = temp_dir("cpp-udl");
        let target = cppfunction("operator\"\"_json_pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-UDL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/json.cpp"),
            target,
            params: vec![
                CppParameter {
                    name: "s".to_owned(),
                    cpp_type: "const char8_t *".to_owned(),
                },
                CppParameter {
                    name: "n".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/json.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        // The length param tracks the buffer, never an independent fuzzed length.
        assert!(
            main.contains("std::size_t n = (std::size_t)(s ? Size : 0)"),
            "UDL length must bind to Size, not a decoupled fuzzed length:\n{main}"
        );
        assert!(
            !main.contains("bhf_bounded_length(&Cur, 0, 65536)"),
            "UDL length must NOT be an independent bounded fuzz length:\n{main}"
        );
        // `s` is still a NUL-terminated copy of the input (safe for both
        // `string(s, n)` and a C-string `string(s)`).
        assert!(
            main.contains("char8_t * s = (const char8_t *)malloc")
                || main.contains("char8_t * s = (char8_t *)malloc"),
            "UDL char buffer must be a NUL-terminated heap copy:\n{main}"
        );
    }

    #[test]
    fn qualified_namespace_free_function_emits_forward_declaration() {
        // A free function in a C++ namespace, discovered from a header-less `.cpp`
        // (no project header declares it), must get a namespace-qualified forward
        // declaration so the qualified call resolves the identifier. Regression for
        // the `use of undeclared identifier 'UtilitiesLib'` codegen bug.
        let out = temp_dir("cpp-qual-ns");
        let mut target = cppfunction("Extract_Minutes");
        target.qualifier_path = vec!["UtilitiesLib".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-QNS001".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/util.cpp"),
            target,
            params: vec![
                CppParameter {
                    name: "g".to_owned(),
                    cpp_type: "char *".to_owned(),
                },
                CppParameter {
                    name: "s".to_owned(),
                    cpp_type: "long".to_owned(),
                },
                CppParameter {
                    name: "l".to_owned(),
                    cpp_type: "long".to_owned(),
                },
                CppParameter {
                    name: "e".to_owned(),
                    cpp_type: "long".to_owned(),
                },
                CppParameter {
                    name: "m".to_owned(),
                    cpp_type: "double *".to_owned(),
                },
            ],
            return_type: "long".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/util.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let src = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            src.contains("namespace UtilitiesLib"),
            "expected ns forward decl:\n{src}"
        );
        assert!(
            src.contains("Extract_Minutes("),
            "forward decl names the fn:\n{src}"
        );
        assert!(
            src.contains("UtilitiesLib::Extract_Minutes("),
            "still calls the qualified name:\n{src}"
        );
    }

    #[test]
    fn global_free_function_gets_a_forward_declaration_when_no_header_declares_it() {
        // A header-less `.cpp` free function still pulls in whatever headers the
        // file includes. Taking their mere presence as proof the TARGET is declared
        // left the harness calling a name nothing had declared:
        //
        //   main.cpp:111:13: error: use of undeclared identifier 'decode_frame'
        //
        // Only a header that actually declares the target may suppress the forward
        // declaration.
        let out = temp_dir("cpp-global-fwd");
        fs::write(
            out.join("sesspp.hpp"),
            "#pragma once\nnamespace ssh { class Session { public: int readFrame(); }; }\n",
        )
        .unwrap();
        let mut target = cppfunction("decode_frame");
        target.return_type = "int".to_owned();
        let args = |includes: Vec<String>| GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-BHFWD01".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("driver.cpp"),
            target: target.clone(),
            params: vec![CppParameter {
                name: "data".to_owned(),
                cpp_type: "const unsigned char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: includes,
            target_includes_dirs: vec![out.clone()],
            target_sources: vec![out.join("driver.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        // A header that does NOT declare it: the forward declaration is required.
        let result = generate_cpp_direct_harness(args(vec!["sesspp.hpp".to_owned()])).unwrap();
        let src = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            src.contains("int decode_frame(const unsigned char *);"),
            "expected a forward declaration:\n{src}"
        );

        // A header that DOES declare it: no forward declaration, as before.
        fs::write(
            out.join("driver.h"),
            "#pragma once\nint decode_frame(const unsigned char *data);\n",
        )
        .unwrap();
        let result = generate_cpp_direct_harness(args(vec!["driver.h".to_owned()])).unwrap();
        let src = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            !src.contains("int decode_frame(const unsigned char *);"),
            "the declaring header makes the forward declaration redundant:\n{src}"
        );
        let _ = fs::remove_dir_all(&out);
    }

    #[test]
    fn forward_declaration_drops_an_export_decoration_the_harness_cannot_see() {
        // A JNI target is declared `JNIEXPORT jstring JNICALL Java_…(…)`. The macro
        // comes from the project's own headers, which the harness does not include,
        // so copying it into the forward declaration manufactures an error the
        // target never had:
        //
        //   main.cpp:64:1: error: unknown type name 'JNIEXPORT'
        //   main.cpp:64:16: error: expected ';' after top level declarator
        assert_eq!(strip_declaration_decoration("JNIEXPORT jstring"), "jstring");
        assert_eq!(
            strip_declaration_decoration("MAGICK_EXPORT Image *"),
            "Image *"
        );
        // A return type that IS an all-caps project typedef must survive: there is
        // nothing after it to be the real type.
        assert_eq!(strip_declaration_decoration("UINT32"), "UINT32");
        assert_eq!(strip_declaration_decoration("HRESULT"), "HRESULT");
        // Ordinary spellings are untouched.
        assert_eq!(strip_declaration_decoration("int"), "int");
        assert_eq!(strip_declaration_decoration("const char *"), "const char *");
        assert_eq!(
            strip_declaration_decoration("std::vector<int>"),
            "std::vector<int>"
        );
        assert_eq!(
            strip_declaration_decoration("unsigned long long"),
            "unsigned long long"
        );
    }

    #[test]
    fn forward_declaration_survives_both_decoration_shapes() {
        // The two strippers cover different macros and the forward declaration
        // needs both: a constant-evaluation macro (utf8.h's `utf8_constexpr14_impl`,
        // lowercase, so the all-caps rule cannot see it) and an export decoration.
        let composed =
            |ty: &str| strip_declaration_decoration(&strip_runtime_illegal_result_specifiers(ty));
        assert_eq!(composed("utf8_constexpr14_impl int"), "int");
        assert_eq!(composed("JNIEXPORT jstring"), "jstring");
        assert_eq!(composed("static inline const char *"), "const char *");
        assert_eq!(composed("int"), "int");
    }

    #[test]
    fn declares_identifier_needs_a_declarator_not_a_substring() {
        assert!(declares_identifier(
            "int decode_frame(const char *);",
            "decode_frame"
        ));
        assert!(declares_identifier(
            "int decode_frame (void);",
            "decode_frame"
        ));
        // A longer name that merely CONTAINS the target, a member access, and a
        // qualified name in another scope are all not declarations of it.
        assert!(!declares_identifier(
            "int decode_frame_v2(void);",
            "decode_frame"
        ));
        assert!(!declares_identifier(
            "int my_decode_frame(void);",
            "decode_frame"
        ));
        assert!(!declares_identifier("x.decode_frame();", "decode_frame"));
        assert!(!declares_identifier("ns::decode_frame();", "decode_frame"));
        assert!(!declares_identifier(
            "extern int decode_frame;",
            "decode_frame"
        ));
    }

    #[test]
    fn qualified_namespace_free_function_with_header_still_emits_forward_declaration() {
        // A namespace-qualified free function gets its forward declaration EVEN
        // when a project header is in scope: the auto-included header (e.g. an MFC
        // `StdAfx.h`) frequently does not declare THIS symbol, and without the decl
        // the qualified call is `use of undeclared identifier` (the reported
        // `UtilitiesLib` bug). A namespace-scoped redeclaration matching the real
        // one is legal C++, so the redundant decl is harmless when the header does
        // declare it.
        let out = temp_dir("cpp-qual-ns-hdr");
        let mut target = cppfunction("Extract_Minutes");
        target.qualifier_path = vec!["UtilitiesLib".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-QNS002".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/util.cpp"),
            target,
            params: vec![CppParameter {
                name: "s".to_owned(),
                cpp_type: "long".to_owned(),
            }],
            return_type: "long".to_owned(),
            target_includes: vec!["util.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: vec![PathBuf::from("/tmp/util.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let src = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            src.contains("namespace UtilitiesLib {"),
            "a namespaced free fn must get a forward decl even with a header in scope:\n{src}"
        );
        assert!(
            src.contains("UtilitiesLib::Extract_Minutes("),
            "still calls the qualified name:\n{src}"
        );
    }

    #[test]
    fn cpp_parameter_type_supported_accepts_floating_point_scalars() {
        // §26.6: by-value `float`/`double` are decodable scalars — the C++
        // lifecycle-step gate (`cpp_parameter_type_supported`) used to reject them,
        // so tinyxml2's `DoubleAttribute(double)`/`FloatAttribute(float)` were
        // skipped "unsupported parameter type 'double'/'float'". They must now be
        // accepted like every other scalar. (By-reference scalars are a separate,
        // pre-existing limitation shared with `const int &`, out of scope here.)
        for ty in ["float", "double", "long double"] {
            assert!(
                cpp_parameter_type_supported(ty),
                "C++ float/double param '{ty}' must be supported (§26.6)"
            );
        }
    }

    #[test]
    fn cpp_parameter_type_supported_accepts_const_qualified_by_value_scalars() {
        // Campaign: taocpp-json skipped lifecycle steps whose params were
        // `const bool`/`const double`/`const int`/... — a top-level const on a
        // BY-VALUE scalar is irrelevant to the caller and must decode like the
        // bare type. The lifecycle-step / direct gate (`cpp_parameter_type_
        // supported`) must now accept them. (Const-references like `const int &`
        // are a separate, pre-existing limitation, out of scope.)
        for ty in [
            "const bool",
            "const double",
            "const float",
            "const int",
            "const unsigned",
            "const long",
            "const std::size_t",
            "const std::uint32_t",
            "bool const",
            "volatile int",
        ] {
            assert!(
                cpp_parameter_type_supported(ty),
                "C++ const-qualified by-value scalar '{ty}' must be supported"
            );
        }
    }

    #[test]
    fn substitute_template_type_params_replaces_whole_identifiers_only() {
        let subst = vec![("T".to_owned(), "int".to_owned())];
        assert_eq!(substitute_template_type_params("T", &subst), "int");
        assert_eq!(
            substitute_template_type_params("const std::vector<T> &", &subst),
            "const std::vector<int> &"
        );
        // `T` inside another identifier (`Tree`, `myT`) must NOT be replaced.
        assert_eq!(substitute_template_type_params("Tree", &subst), "Tree");
        assert_eq!(
            substitute_template_type_params("std::pair<T, T>", &subst),
            "std::pair<int, int>"
        );
        // Multiple params.
        let multi = vec![
            ("K".to_owned(), "std::string".to_owned()),
            ("V".to_owned(), "double".to_owned()),
        ];
        assert_eq!(
            substitute_template_type_params("std::map<K, V>", &multi),
            "std::map<std::string, double>"
        );
        // Empty subst is a no-op.
        assert_eq!(substitute_template_type_params("T", &[]), "T");
    }

    #[test]
    fn generate_cpp_direct_harness_instantiates_template_with_turbofish() {
        // #455 / §27.5: a templated free function with a resolved specialization
        // emits a turbofish call and substitutes the type arg into the decoded
        // parameter / result types.
        let out = temp_dir("cpp-template");
        let mut target = cppfunction("convert");
        target.api.is_template = true;
        target.api.api_kind = "template_function".to_owned();
        target.template_type_params = vec!["T".to_owned()];
        target.instantiation_args = vec!["int".to_owned()];
        target.return_type = "T".to_owned();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPTPL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/convert.hpp"),
            target,
            params: vec![CppParameter {
                name: "data".to_owned(),
                cpp_type: "const std::vector<T> &".to_owned(),
            }],
            return_type: "T".to_owned(),
            target_includes: vec!["convert.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("convert<int>(data)"),
            "expected a turbofish call:\n{main}"
        );
        // The result variable's `T` is specialised to `int`.
        assert!(
            main.contains("int R = convert<int>(data)"),
            "expected substituted result type:\n{main}"
        );
        // The decoded parameter's `T` is specialised to `int`.
        assert!(
            main.contains("std::vector<int>"),
            "expected substituted parameter type:\n{main}"
        );
    }

    #[test]
    fn return_type_macro_shaped_token_detection() {
        // Multi-segment all-caps decoration macros are detected (so the emitter can
        // fall back to `auto`); single-word real all-caps types and ordinary
        // lower/mixed-case types are NOT, and so keep their explicit result type.
        assert!(return_type_has_macro_shaped_token(
            "FOO_EXTERNAL_LINKAGE parse_result"
        ));
        assert!(return_type_has_macro_shaped_token(
            "parse_result FOO_CALLCONV"
        ));
        assert!(return_type_has_macro_shaped_token("TOML_CALLCONV"));
        assert!(!return_type_has_macro_shaped_token("parse_result"));
        assert!(!return_type_has_macro_shaped_token("int"));
        assert!(!return_type_has_macro_shaped_token("const char *"));
        assert!(!return_type_has_macro_shaped_token("std::string"));
        assert!(!return_type_has_macro_shaped_token("uint32_t"));
        // Single-word real all-caps types have no underscore, so they are kept.
        assert!(!return_type_has_macro_shaped_token("DWORD"));
        assert!(!return_type_has_macro_shaped_token("BYTE"));
    }

    #[test]
    fn cpp_result_var_falls_back_to_auto_for_unexpanded_decoration_macro() {
        // A library decoration macro the parser + c-decoration strippers both miss
        // (toml++ wraps results in `..._EXTERNAL_LINKAGE` / `..._CALLCONV`) would
        // otherwise leak into the result-variable TYPE — and the header `#undef`s it,
        // so `<ret> R = call();` won't compile. The emitter falls back to
        // `auto R = call();`, which deduces the real type and always compiles.
        let out = temp_dir("cpp-auto-fallback");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPAUTO".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/toml.hpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "doc".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "FOO_EXTERNAL_LINKAGE parse_result".to_owned(),
            target_includes: vec!["toml.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("auto R = parse("),
            "expected `auto` result-var fallback:\n{main}"
        );
        assert!(
            !main.contains("EXTERNAL_LINKAGE"),
            "the unexpanded decoration macro must not leak into the result var:\n{main}"
        );
    }

    #[test]
    fn cpp_result_var_strips_constexpr_macro_return_qualifier() {
        // utf8.h declares `utf8_constexpr14_impl int utf8cmp(...)` where the macro
        // expands to `constexpr` under C++14. The harness does not preprocess the
        // header, so the literal token `utf8_constexpr14_impl` reaches codegen as a
        // leading return-type qualifier. Emitting `utf8_constexpr14_impl int R =
        // <runtime call>;` is rejected ("constexpr variable 'R' must be initialized
        // by a constant expression"). The qualifier must be stripped from the
        // result-variable type, leaving the bare `int`.
        let out = temp_dir("cpp-constexpr-macro");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPCE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/utf8.h"),
            target: cppfunction("utf8cmp"),
            params: vec![CppParameter {
                name: "src1".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "utf8_constexpr14_impl int".to_owned(),
            target_includes: vec!["utf8.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("int R = utf8cmp("),
            "result var must declare the bare `int` type:\n{main}"
        );
        assert!(
            !main.contains("constexpr"),
            "constexpr-expanding macro qualifier must be stripped from result var:\n{main}"
        );
    }

    #[test]
    fn cpp_result_var_keeps_const_pointee_return_type() {
        // Regression guard: `const char *` is a const *pointee*, not an illegal
        // local-var specifier. `const char * R = call();` is perfectly legal and the
        // const must NOT be stripped (doing so would make assigning a `const char *`
        // return into a `char *` local ill-formed).
        let out = temp_dir("cpp-const-pointee");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPCP".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("name_of"),
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "const char *".to_owned(),
            target_includes: vec!["demo.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("const char * R = name_of(") || main.contains("const char *R = name_of("),
            "const pointee return type must be preserved verbatim:\n{main}"
        );
    }

    #[test]
    fn cpp_project_include_dirs_use_iquote_so_system_headers_win() {
        // #366 (C++ mirror): project include dirs must be -iquote (not -I or
        // -isystem) so a vendored header (capnproto's C++ endian.h) cannot
        // shadow a system header of the same name pulled in via angle include.
        let out = temp_dir("cpp-iquote");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPISYS".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["demo.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/proj/inc")],
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/rt"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let mk = fs::read_to_string(&result.makefile).unwrap();
        assert!(
            mk.contains("-iquote /proj/inc"),
            "project include dirs must be passed as -iquote: {mk}"
        );
        assert!(
            mk.contains("-idirafter /proj/inc"),
            "project include dirs must ALSO be -idirafter so angled self-includes resolve: {mk}"
        );
        assert!(
            !mk.contains("-I /proj/inc"),
            "project include dirs must NOT be passed as -I: {mk}"
        );
        assert!(
            !mk.contains("-isystem /proj/inc"),
            "-isystem does not prevent shadowing; must be -iquote: {mk}"
        );
        assert!(mk.contains("-I ."), "harness cwd must stay -I .: {mk}");
        assert!(
            mk.contains("-I /rt"),
            "c_runtime include must stay -I: {mk}"
        );
    }

    #[test]
    fn constructor_target_is_direct_initialized_not_called_as_a_method() {
        // A constructor target (capnp `Text::Reader::Reader`) must be emitted as
        // direct-initialization `Text::Reader _bhf_receiver(args);`, NOT as a member
        // call `_bhf_receiver.Reader(args)` — naming a constructor as a member is
        // illegal C++ ("invalid use of 'capnp::Text::Reader::Reader'").
        let out = temp_dir("cpp-ctor-target");
        let mut target = cppfunction("Reader");
        target.qualifier_path = vec!["capnp".to_owned(), "Text".to_owned(), "Reader".to_owned()];
        target.api.is_method = true;
        target.api.is_constructor = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CTOR01".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/text.h"),
            target,
            params: vec![CppParameter {
                name: "n".to_owned(),
                cpp_type: "std::uint32_t".to_owned(),
            }],
            return_type: String::new(),
            target_includes: vec!["capnp/text.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(
            main.contains("capnp::Text::Reader _bhf_receiver(n);"),
            "constructor target must be direct-initialized:\n{main}"
        );
        assert!(
            !main.contains("_bhf_receiver.Reader("),
            "constructor must not be called as a member function:\n{main}"
        );
    }

    #[test]
    fn generate_cpp_sequence_harness_constructs_receiver_from_decoded_constructor_params() {
        let out = temp_dir("cpp-sequence-ctor");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["gov".to_owned(), "Parser".to_owned()];
        target.api.class_name = Some("Parser".to_owned());
        target.api.namespace_path = vec!["gov".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CPP-CTOR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/parser.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "std::string_view".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/parser.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: vec![CppParameter {
                name: "seed".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            lifecycle_steps: Vec::new(),
            protocol_steps: vec![
                CppProtocolStep {
                    step: CppLifecycleStep {
                        name: "configure".to_owned(),
                        params: vec![CppParameter {
                            name: "mode".to_owned(),
                            cpp_type: "int".to_owned(),
                        }],
                        return_type: "void".to_owned(),
                    },
                    args: vec![CppProtocolArg::Literal("7".to_owned())],
                    marks_target: false,
                },
                CppProtocolStep {
                    step: CppLifecycleStep {
                        name: "parse".to_owned(),
                        params: vec![CppParameter {
                            name: "input".to_owned(),
                            cpp_type: "std::string_view".to_owned(),
                        }],
                        return_type: "int".to_owned(),
                    },
                    args: vec![CppProtocolArg::Decode],
                    marks_target: true,
                },
            ],
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();

        assert!(main.contains("std::string _bhf_ctor_seed"));
        assert!(main.contains("gov::Parser _bhf_receiver(_bhf_ctor_seed);"));
        assert!(main.contains("_bhf_receiver.parse(_bhf_protocol1_input);"));
        assert!(
            !main.contains("BHF_KEEP_RESULT(R);"),
            "a mined protocol names per-step results, so no nonexistent direct-call R may remain: {main}"
        );
        let configure = main.find("_bhf_receiver.configure(7)").unwrap();
        let parse = main.find("_bhf_receiver.parse(").unwrap();
        assert!(
            configure < parse,
            "expert protocol order must be retained: {main}"
        );
        assert!(
            makefile.contains("cov: main_cov") && makefile.contains("$(COV_CXX)"),
            "C++ protocols must remain measurable by coverage replay: {makefile}"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_substitutes_abstract_receiver_with_subclass() {
        // #456: an abstract declaring class is replaced by the caller-resolved
        // concrete subclass for the receiver, so the virtual method dispatches
        // polymorphically (`MemoryReader::read`).
        let out = temp_dir("cpp-abstract-subclass");
        let mut target = cppfunction("read");
        target.qualifier_path = vec!["e57".to_owned(), "Reader".to_owned()];
        target.api.class_name = Some("Reader".to_owned());
        target.api.namespace_path = vec!["e57".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-ABS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/reader.cpp"),
            target,
            params: vec![CppParameter {
                name: "n".to_owned(),
                cpp_type: "int".to_owned(),
            }],
            return_type: "void".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/reader.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: Some("e57::MemoryReader".to_owned()),
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        // The receiver is the concrete subclass, not the abstract base.
        assert!(main.contains("e57::MemoryReader _bhf_receiver"), "{main}");
        assert!(!main.contains("e57::Reader _bhf_receiver"), "{main}");
        // The virtual method is still called on the receiver.
        assert!(main.contains("_bhf_receiver.read("), "{main}");
    }

    #[test]
    fn generate_cpp_direct_harness_makefile_includes_afl_target() {
        let out = temp_dir("cpp-emit-afl");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-AFL".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();

        assert!(main.contains("extern \"C\" int bhf_run_one"));
        assert!(main.contains("BHF_KEEP_RESULT(R)"));
        assert!(main.contains("#ifndef BHF_EXTERNAL_DRIVER"));
        assert!(main.contains("#if defined(BHF_AFL)"));
        assert!(main.contains("__AFL_LOOP(10000)"));
        assert!(main.contains("#else"));
        assert!(main.contains("int LLVMFuzzerTestOneInput"));
        assert!(makefile.contains("ifeq ($(origin CXX), default)"));
        assert!(makefile.contains("CXX = clang++"));
        assert!(makefile.contains(".PHONY: all afl libfuzzer cov diff syntaxcheck clean"));
        assert!(makefile.contains("AFLPP_CXX ?= afl-clang-fast++"));
        assert!(makefile.contains("afl: main_afl"));
        assert!(makefile.contains("libfuzzer: main_libfuzzer"));
        assert!(makefile.contains("LIBFUZZER_CXX ?= clang++"));
        assert!(makefile.contains("cov: main_cov"));
        assert!(makefile.contains("COV_CXX ?= clang++"));
        // The two-compiler differential build target.
        assert!(makefile.contains("diff: main_diff"));
        assert!(makefile.contains("DIFF_CXX ?= clang++"));
        assert!(makefile.contains("bhf_driver.o: $(BHF_DRIVER_SOURCE)"));
        // The driver TU is compiled as C with the driver flags. It also needs the
        // POSIX feature-test macros: the driver calls `mkstemp`/`ftruncate`, and a
        // strict `-std=` from the project's compile database otherwise leaves them
        // undeclared.
        assert!(makefile.contains("$(CXX) -x c $(BHF_DRIVER_CFLAGS)"));
        assert!(makefile.contains("$(FEATURE_TEST_FLAGS) -c -o $@ $(BHF_DRIVER_SOURCE)"));
        assert!(makefile.contains("FEATURE_TEST_FLAGS ?= -D_GNU_SOURCE -D_DEFAULT_SOURCE"));
        assert!(makefile.contains("-DBHF_EXTERNAL_DRIVER -o $@ main.cpp"));
        // The afl target is declared; target sources live in the recipe, not the
        // prerequisites (an absolute Windows source path carries a drive-letter
        // colon that GNU make would parse as a target:prereq separator).
        assert!(makefile.contains("main_afl: main.cpp"));
        // …and the afl recipe still compiles the target source alongside main.cpp.
        assert!(makefile.contains("-o $@ main.cpp /tmp/source.cpp"));
        assert!(makefile.contains("$(AFLPP_CXX) $(AFLPP_CXXFLAGS)"));
        assert!(makefile.contains("-DBHF_AFL"));
        assert!(
            makefile.contains("SECTION_FLAGS ?= -ffunction-sections -fdata-sections")
                && makefile.contains("SECTION_LDFLAGS ?= -Wl,--gc-sections"),
            "C++ harnesses must discard unreachable dependency sections:\n{makefile}"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_handles_vector_uint8() {
        let out = temp_dir("cpp-emit-vec");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP002".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("decode"),
            params: vec![CppParameter {
                name: "buf".to_owned(),
                cpp_type: "const std::vector<uint8_t> &".to_owned(),
            }],
            return_type: "void".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("std::vector<uint8_t> buf(Data, Data + Size)"));
        assert!(
            !main.contains("R = decode"),
            "void return should not bind R"
        );
    }

    #[test]
    fn generate_cpp_direct_harness_handles_vector_string() {
        let out = temp_dir("cpp-emit-vector-string");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP010".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse_args"),
            params: vec![CppParameter {
                name: "tokens".to_owned(),
                cpp_type: "const std::vector<std::string> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("std::vector<std::string> tokens;"));
        assert!(main.contains("parse_args(tokens);"));
    }

    #[test]
    fn generate_cpp_direct_harness_handles_vector_of_supported_values() {
        let out = temp_dir("cpp-emit-vector-scalar");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VECTOR-SCALAR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::vector<std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("std::vector<std::uint32_t> items;"));
        assert!(main.contains("items.emplace_back(_bhf_vector_items_elt)"));
        assert!(main.contains("parse(items);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_deque_and_list() {
        let out = temp_dir("cpp-emit-sequence-containers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SEQUENCE-CONTAINERS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "items".to_owned(),
                    cpp_type: "const std::deque<std::uint32_t> &".to_owned(),
                },
                CppParameter {
                    name: "views".to_owned(),
                    cpp_type: "const std::list<std::string_view> &".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <deque>"));
        assert!(main.contains("#include <list>"));
        assert!(main.contains("std::deque<std::uint32_t> items;"));
        assert!(main.contains("std::list<std::string_view> views;"));
        assert!(main.contains("parse(items, views);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_forward_list() {
        let out = temp_dir("cpp-emit-forward-list");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-FORWARD-LIST".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::forward_list<std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <forward_list>"));
        assert!(main.contains("std::forward_list<std::uint32_t> items;"));
        assert!(main.contains("items.emplace_front(_bhf_forward_list_items_elt)"));
        assert!(main.contains("parse(items);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_set_and_map() {
        let out = temp_dir("cpp-emit-associative-containers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ASSOCIATIVE-CONTAINERS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "ids".to_owned(),
                    cpp_type: "const std::set<std::uint32_t> &".to_owned(),
                },
                CppParameter {
                    name: "lookup".to_owned(),
                    cpp_type: "const std::map<std::string_view, std::uint32_t> &".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <map>"));
        assert!(main.contains("#include <set>"));
        assert!(main.contains("std::set<std::uint32_t> ids;"));
        assert!(main.contains("std::map<std::string_view, std::uint32_t> lookup;"));
        assert!(main.contains("lookup.emplace(_bhf_map_lookup_key, _bhf_map_lookup_value)"));
        assert!(main.contains("parse(ids, lookup);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_unordered_set_and_map() {
        let out = temp_dir("cpp-emit-unordered-associative-containers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-UNORDERED-ASSOCIATIVE-CONTAINERS".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "ids".to_owned(),
                    cpp_type: "const std::unordered_set<std::uint32_t> &".to_owned(),
                },
                CppParameter {
                    name: "lookup".to_owned(),
                    cpp_type: "const std::unordered_map<std::string_view, std::uint32_t> &"
                        .to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <unordered_map>"));
        assert!(main.contains("#include <unordered_set>"));
        assert!(main.contains("std::unordered_set<std::uint32_t> ids;"));
        assert!(main.contains("std::unordered_map<std::string_view, std::uint32_t> lookup;"));
        assert!(main.contains(
            "lookup.emplace(_bhf_unordered_map_lookup_key, _bhf_unordered_map_lookup_value)"
        ));
        assert!(main.contains("parse(ids, lookup);"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_cpp_struct_by_value_with_registry() {
        let out = temp_dir("cpp-emit-struct-by-value");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STRUCT".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("consume"),
            params: vec![CppParameter {
                name: "cfg".to_owned(),
                cpp_type: "Config".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["api.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![
                        c_parser::CParamDescriptor {
                            name: "mode".to_owned(),
                            c_type: "int".to_owned(),
                        },
                        c_parser::CParamDescriptor {
                            name: "enabled".to_owned(),
                            c_type: "bool".to_owned(),
                        },
                        c_parser::CParamDescriptor {
                            name: "code".to_owned(),
                            c_type: "std::uint16_t".to_owned(),
                        },
                    ],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        // C++ value-initializes the aggregate (`Config cfg{};`) rather than
        // declaring + memset-zeroing it — memset on a non-trivial class is UB.
        assert!(main.contains("Config cfg{}"));
        assert!(
            !main.contains("memset(&cfg"),
            "C++ struct must be value-initialized, not memset:\n{main}"
        );
        assert!(main.contains("cfg.mode = bhf_i32(&Cur)"));
        assert!(main.contains("cfg.enabled = (bool)(bhf_u8(&Cur) & 1)"));
        assert!(main.contains("cfg.code = (std::uint16_t)bhf_bounded_i32(&Cur, 0, 0xffff)"));
        assert!(main.contains("consume(cfg);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_source_for_source_only_aggregate_reference() {
        let out = temp_dir("cpp-emit-struct-ref");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STRUCT-REF".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("consume"),
            params: vec![CppParameter {
                name: "cfg".to_owned(),
                cpp_type: "const Config &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include \"x.cpp\""));
        assert!(!main.contains("int consume("));
        assert!(main.contains("Config cfg"));
        assert!(main.contains("cfg.mode = bhf_i32(&Cur)"));
        assert!(main.contains("consume(cfg);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_drives_file_pointer_with_fmemopen() {
        let work = temp_dir("cpp-emit-file-pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-FILE".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse_stream"),
            params: vec![CppParameter {
                name: "stream".to_owned(),
                cpp_type: "FILE *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <stdio.h>"));
        assert!(main.contains("fmemopen(_bhf_file_buf_stream, Size, \"r+\")"));
        assert!(main.contains("Size ? fmemopen"));
        assert!(main.contains(": tmpfile()"));
        assert!(main.contains("int R = parse_stream(stream);"));
        assert!(main.contains("if (stream) fclose(stream); free(_bhf_file_buf_stream);"));

        let Some(cxx_flags) = clangxx_compile_flags("cppgen-file-pointer") else {
            eprintln!(
                "skipping generated C++ FILE* harness compile: clang++ C++ headers unavailable"
            );
            return;
        };
        let obj = work.join("file_main.o");
        let output = Command::new("clang++")
            .args(&cxx_flags)
            .arg("-std=c++17")
            .arg("-I")
            .arg(runtime_dir())
            .arg("-c")
            .arg(&result.main_cpp)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang++");
        assert!(
            output.status.success(),
            "clang++ failed\nstdout:\n{}\nstderr:\n{}\nmain.cpp:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn generate_cpp_direct_harness_drives_std_file_pointer_with_fmemopen() {
        let work = temp_dir("cpp-emit-std-file-pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STD-FILE".to_owned(),
            output_dir: work.join("harness"),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse_stream"),
            params: vec![CppParameter {
                name: "stream".to_owned(),
                cpp_type: "std::FILE *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("fmemopen(_bhf_file_buf_stream, Size, \"r+\")"));
        assert!(main.contains("parse_stream(stream);"));
        assert!(main.contains("if (stream) fclose(stream); free(_bhf_file_buf_stream);"));
    }

    #[test]
    fn generate_cpp_direct_harness_emits_callback_trampoline_for_typedef() {
        let out = temp_dir("cpp-emit-callback");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-CB".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("visit"),
            params: vec![CppParameter {
                name: "cb".to_owned(),
                cpp_type: "visit_cb".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["api.hpp".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                typedefs: vec![c_parser::CTypedefDef {
                    name: "visit_cb".to_owned(),
                    underlying: "int (*)(void *opaque, const char *name)".to_owned(),
                    line: 1,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("static int _bhf_cb_trampoline(void *opaque, const char *name)"));
        assert!(main.contains("visit_cb cb = (visit_cb)_bhf_cb_trampoline;"));
        assert!(main.contains("int R = visit(cb);"));
    }

    #[test]
    fn generate_cpp_direct_harness_emits_std_function_callback() {
        let out = temp_dir("cpp-emit-std-function-callback");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-STDFUNC".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("walk"),
            params: vec![CppParameter {
                name: "cb".to_owned(),
                cpp_type: "const std::function<int(std::string_view)> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <functional>"));
        assert!(main.contains(
            "std::function<int(std::string_view)> cb = [](std::string_view _bhf_cb_arg0) -> int"
        ));
        assert!(main.contains("(void)_bhf_cb_arg0;"));
        assert!(main.contains("return {};"));
        assert!(main.contains("int R = walk(cb);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_array_for_fixed_array() {
        let out = temp_dir("cpp-emit-array");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP009".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "key".to_owned(),
                cpp_type: "const std::array<std::byte, 16> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <array>"));
        assert!(main.contains("std::array<std::byte, 16> key{}"));
        assert!(main.contains("parse(key);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_array_for_supported_values() {
        let out = temp_dir("cpp-emit-array-values");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ARRAY-VALUES".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "values".to_owned(),
                cpp_type: "const std::array<std::uint32_t, 4> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <array>"));
        assert!(main.contains("std::array<std::uint32_t, 4> values{}"));
        assert!(main.contains("values[_bhf_i_values] = _bhf_array_values_elt"));
        assert!(main.contains("parse(values);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_bitset_for_bitset() {
        let out = temp_dir("cpp-emit-bitset");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-BITSET".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "flags".to_owned(),
                cpp_type: "const std::bitset<32> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <bitset>"));
        assert!(main.contains("std::bitset<32> flags"));
        assert!(main.contains("flags.set(_bhf_i_flags"));
        assert!(main.contains("parse(flags);"));
    }

    #[test]
    fn generated_cpp_harness_names_its_input_format_version() {
        let out = temp_dir("cpp-format-version");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPPFMT".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/source.cpp"),
            target: cppfunction("parse_record"),
            params: vec![CppParameter {
                name: "flags".to_owned(),
                cpp_type: "unsigned int".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/source.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let stamp = format!("// bhf harness format {}", crate::HARNESS_FORMAT_VERSION);
        assert!(main.contains(&stamp), "missing {stamp:?} in:\n{main}");
        fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn cpp_buffer_pairing_requires_name_evidence() {
        let reg = type_model::TypeRegistry::default();
        let decls = |params: &[(&str, &str)]| -> String {
            let p: Vec<CppParameter> = params
                .iter()
                .map(|(n, t)| CppParameter {
                    name: (*n).to_owned(),
                    cpp_type: (*t).to_owned(),
                })
                .collect();
            build_cpp_param_decoders(&p, &reg, &[], &CppDecoderLimits::default(), false, false)
                .unwrap()
                .iter()
                .map(|e| e.decl.clone())
                .collect::<Vec<_>>()
                .join(" ; ")
        };
        // pugixml load_file(const char *path_, unsigned int options): neither name
        // is buffer- nor length-shaped, so it must NOT pair (binding path_ to the
        // raw non-NUL Data span was a heap-buffer-overflow FALSE POSITIVE).
        let nogate = decls(&[("path_", "const char *"), ("options", "unsigned int")]);
        assert!(
            !nogate.contains("path_ = (const char *)Data"),
            "path_/options must not be mis-paired as (buffer, length): {nogate}"
        );
        // A genuine (const char *data, size_t len) pair still binds to (Data, Size).
        let paired = decls(&[("data", "const char *"), ("len", "size_t")]);
        assert!(
            paired.contains(")Data") && paired.contains(")Size"),
            "data/len must still pair to (Data, Size): {paired}"
        );
        // A mutable input/in-out pair needs a writable copy. Pointing it at
        // libFuzzer's const Data makes a legitimate in-place write look like a
        // target bug. The length must also collapse to zero if malloc fails.
        let mutable = decls(&[("data", "uint8_t *"), ("len", "size_t")]);
        assert!(
            mutable.contains("uint8_t * data = (uint8_t *)malloc(_bhf_cap_data")
                && mutable.contains("memcpy(data, Data, _bhf_cap_data)")
                && mutable.contains("len = (size_t)(data ? _bhf_cap_data : 0)"),
            "mutable data/len must use a coherent writable copy: {mutable}"
        );
    }

    fn cpp_param_decls(
        registry: &type_model::TypeRegistry,
        params: &[(&str, &str)],
    ) -> Vec<String> {
        let params: Vec<CppParameter> = params
            .iter()
            .map(|(name, cpp_type)| CppParameter {
                name: (*name).to_owned(),
                cpp_type: (*cpp_type).to_owned(),
            })
            .collect();
        build_cpp_param_decoders(
            &params,
            registry,
            &[],
            &CppDecoderLimits::default(),
            false,
            false,
        )
        .expect("decoders")
        .into_iter()
        .map(|emission| emission.decl)
        .collect()
    }

    fn typedef_registry(source: &str) -> type_model::TypeRegistry {
        let defs = c_parser::parse_c_type_defs(source).expect("type defs");
        type_model::TypeRegistry::from_defs(std::iter::once(&defs))
    }

    #[test]
    fn cpp_buffer_pairing_resolves_typedefs_on_both_sides() {
        let registry = typedef_registry(
            "typedef unsigned char u8_t;\n\
             typedef unsigned int u32_t;\n\
             typedef u8_t octet_t;\n",
        );
        for (buffer, length, buf_decl, len_decl) in [
            (
                ("buf", "const u8_t *"),
                ("len", "size_t"),
                "const u8_t * buf = (const u8_t *)Data",
                "size_t len = (size_t)Size",
            ),
            (
                ("buf", "const u8_t *"),
                ("len", "u32_t"),
                "const u8_t * buf = (const u8_t *)Data",
                "u32_t len = (u32_t)Size",
            ),
            // A typedef chain resolves too.
            (
                ("bytes", "const octet_t *"),
                ("count", "size_t"),
                "const octet_t * bytes = (const octet_t *)Data",
                "size_t count = (size_t)Size",
            ),
            (
                ("data", "const unsigned char *"),
                ("dataLen", "UINT"),
                "const unsigned char * data = (const unsigned char *)Data",
                "UINT dataLen = (UINT)Size",
            ),
            (
                ("pbData", "const BYTE *"),
                ("cbData", "DWORD"),
                "const BYTE * pbData = (const BYTE *)Data",
                "DWORD cbData = (DWORD)Size",
            ),
        ] {
            let decls = cpp_param_decls(&registry, &[buffer, length]);
            assert_eq!(decls[0], buf_decl, "{buffer:?}/{length:?}: {decls:?}");
            assert_eq!(decls[1], len_decl, "{buffer:?}/{length:?}: {decls:?}");
        }

        // A writable typedef'd buffer gets a coherent copy whose length tracks it.
        let mutable = cpp_param_decls(&registry, &[("buf", "u8_t *"), ("len", "size_t")]);
        assert!(
            mutable[0].contains("u8_t * buf = (u8_t *)malloc(_bhf_cap_buf")
                && mutable[1] == "size_t len = (size_t)(buf ? _bhf_cap_buf : 0)",
            "{mutable:?}"
        );
    }

    #[test]
    fn cpp_buffer_name_alone_does_not_bind_the_next_integer_to_the_input_length() {
        let registry = typedef_registry("typedef unsigned char u8_t;\n");
        let decls = cpp_param_decls(
            &registry,
            &[
                ("src", "const unsigned char *"),
                ("offset", "unsigned int"),
                ("size", "unsigned int"),
            ],
        );
        let joined = decls.join(" ; ");
        assert!(
            !decls[0].contains("= (const unsigned char *)Data")
                && decls[0].contains("malloc(")
                && decls[0].contains("memcpy("),
            "src must be its own heap copy of the input, so its true size is \
             visible to ASan: {joined}"
        );
        assert!(
            !decls[1].contains("Size"),
            "offset must be decoded, not bound to Size: {joined}"
        );
        assert!(
            decls[1].contains("bhf_i32(&Cur)") && !decls[1].contains("bhf_bounded_i32"),
            "offset must be decoded across its full unsigned range: {joined}"
        );

        for (buffer, length) in [
            (("data", "const char *"), ("flags", "int")),
            (("buf", "const uint8_t *"), ("index", "size_t")),
            (("buf", "const u8_t *"), ("start", "size_t")),
            (
                ("input", "const std::byte *"),
                ("bit_index", "unsigned long"),
            ),
        ] {
            let decls = cpp_param_decls(&registry, &[buffer, length]);
            assert!(
                !decls[1].contains("Size"),
                "{length:?} must not be bound to Size after {buffer:?}: {decls:?}"
            );
        }

        // Count-shaped names keep pairing.
        let paired = cpp_param_decls(&registry, &[("src", "const char *"), ("srclen", "int")]);
        assert_eq!(paired[0], "const char * src = (const char *)Data");
        assert_eq!(paired[1], "int srclen = (int)Size");
    }

    #[test]
    fn cpp_common_length_abbreviations_pair_with_their_buffer() {
        let registry = typedef_registry("typedef unsigned char u8_t;\n");
        for (buffer, length) in [
            (("data", "const char *"), ("sz", "std::size_t")),
            (("in", "const unsigned char *"), ("inl", "int")),
            (("buf", "const void *"), ("bytes", "size_t")),
            (("buf", "const char *"), ("bufsiz", "int")),
            (("buf", "const u8_t *"), ("cnt", "unsigned int")),
        ] {
            let decls = cpp_param_decls(&registry, &[buffer, length]);
            let (buf_name, buf_type) = buffer;
            let (len_name, len_type) = length;
            assert_eq!(
                decls[0],
                format!("{buf_type} {buf_name} = ({buf_type})Data"),
                "{decls:?}"
            );
            assert_eq!(
                decls[1],
                format!("{len_type} {len_name} = ({len_type})Size"),
                "{decls:?}"
            );
        }
        for (buffer, length) in [
            (("data", "const char *"), ("account_id", "int")),
            (("buf", "const unsigned char *"), ("caps", "unsigned int")),
        ] {
            let decls = cpp_param_decls(&registry, &[buffer, length]);
            assert!(
                !decls[1].contains("Size"),
                "{length:?} must not be bound to Size after {buffer:?}: {decls:?}"
            );
        }
    }

    /// An output buffer's capacity is a length too: an offset, index or flags
    /// parameter bound to it pointed every write at (or past) the end of the
    /// allocation, including for a typedef'd byte pointer (`u8_t *dst`).
    #[test]
    fn cpp_output_buffers_never_bind_an_offset_or_index_to_their_capacity() {
        let registry = typedef_registry("typedef unsigned char u8_t;\n");
        for params in [
            vec![
                ("dst", "u8_t *"),
                ("offset", "unsigned int"),
                ("n", "unsigned int"),
            ],
            vec![
                ("dst", "unsigned char *"),
                ("offset", "unsigned int"),
                ("size", "unsigned int"),
            ],
            vec![("out", "char *"), ("index", "int")],
            vec![("buf", "char *"), ("offset", "size_t *")],
            vec![("out", "u8_t *"), ("flags", "int")],
            vec![("dest", "BYTE *"), ("pos", "DWORD")],
        ] {
            let decls = cpp_param_decls(&registry, &params);
            let buffer = params[0].0;
            assert!(
                !decls[1].contains(&format!("_bhf_cap_{buffer}")) && !decls[1].contains("Size"),
                "{:?} must not be bound to the capacity of {buffer}: {decls:?}",
                params[1]
            );
        }

        // Count-named capacities keep pairing with their output buffer.
        for (params, len_decl) in [
            (
                vec![("out", "char *"), ("outlen", "size_t")],
                "size_t outlen = (size_t)(out ? _bhf_cap_out : 0)",
            ),
            (
                vec![("dst", "u8_t *"), ("dstCapacity", "size_t")],
                "size_t dstCapacity = (size_t)(dst ? _bhf_cap_dst : 0)",
            ),
        ] {
            let decls = cpp_param_decls(&registry, &params);
            assert_eq!(decls[1], len_decl, "{decls:?}");
        }
        let decls = cpp_param_decls(&registry, &[("out", "char *"), ("outLen", "size_t *")]);
        assert!(
            decls[1].contains("_bhf_out_outLen = (size_t)(out ? _bhf_cap_out : 0)"),
            "{decls:?}"
        );
    }

    /// A byte buffer spelled through a POINTER typedef (`LPCBYTE`, `PBYTE`,
    /// `typedef const u8_t *cu8_ptr`) pairs with its length. The typedef hides
    /// whether the bytes are const, so the buffer is a heap copy of the input and
    /// the length is that copy's size: correct for a read-only and a writable
    /// buffer alike.
    #[test]
    fn cpp_pointer_typedef_byte_buffers_pair_with_their_length() {
        let registry = typedef_registry(
            "typedef unsigned char u8_t;\n\
             typedef const u8_t *cu8_ptr;\n\
             typedef const BYTE *LPCBYTE;\n\
             typedef BYTE *PBYTE;\n",
        );
        for (buffer, length) in [
            (("pbData", "LPCBYTE"), ("cbData", "DWORD")),
            (("buf", "cu8_ptr"), ("len", "size_t")),
            (("pbOut", "PBYTE"), ("cbOut", "ULONG")),
        ] {
            let decls = cpp_param_decls(&registry, &[buffer, length]);
            let (buf_name, buf_type) = buffer;
            let (len_name, len_type) = length;
            assert!(
                decls[0].contains(&format!("{buf_type} {buf_name} = ({buf_type})malloc("))
                    && decls[0].contains(&format!(
                        "memcpy((void *){buf_name}, Data, _bhf_cap_{buf_name})"
                    )),
                "{buffer:?} must be a heap copy of the input: {decls:?}"
            );
            assert_eq!(
                decls[1],
                format!(
                    "{len_type} {len_name} = ({len_type})({buf_name} ? _bhf_cap_{buf_name} : 0)"
                ),
                "the length must track the copy: {decls:?}"
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_pairs_standard_byte_pointer_and_length() {
        for (name, cpp_type, expected_decl) in [
            (
                "std-uint8",
                "const std::uint8_t *",
                "const std::uint8_t * data = (const std::uint8_t *)Data",
            ),
            (
                "std-byte",
                "const std::byte *",
                "const std::byte * data = (const std::byte *)Data",
            ),
        ] {
            let out = temp_dir(name);
            let args = GenerateCppDirectArgs {
                decoder_limits: Default::default(),
                force: false,
                harness_id: "H-CPP004".to_owned(),
                output_dir: out,
                source_path: PathBuf::from("/tmp/x.cpp"),
                target: cppfunction("parse"),
                params: vec![
                    CppParameter {
                        name: "data".to_owned(),
                        cpp_type: cpp_type.to_owned(),
                    },
                    CppParameter {
                        name: "len".to_owned(),
                        cpp_type: "std::size_t".to_owned(),
                    },
                ],
                return_type: "int".to_owned(),
                target_includes: Vec::new(),
                target_includes_dirs: Vec::new(),
                target_sources: Vec::new(),
                compile_flags: Vec::new(),
                c_runtime_include: PathBuf::from("/tmp/c_runtime"),
                using_namespaces: Vec::new(),
                result_cleanup: None,
                constructor_params: Vec::new(),
                type_defs: Vec::new(),
                default_constructible_classes: Vec::new(),
                parameter_constructions: Vec::new(),
                receiver_class_override: None,
                factory_plan: None,
            };

            let result = generate_cpp_direct_harness(args).unwrap();
            let main = fs::read_to_string(&result.main_cpp).unwrap();
            assert!(
                main.contains(expected_decl),
                "expected {cpp_type} pointer to borrow Data, got:\n{main}"
            );
            assert!(
                main.contains("std::size_t len = (std::size_t)Size"),
                "expected std::size_t length to mirror Size, got:\n{main}"
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_output_capacity_does_not_consume_input_pair() {
        let out = temp_dir("cpp-emit-output-capacity");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OUT-CAP".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("compress_mem_to_mem"),
            params: vec![
                CppParameter {
                    name: "pOut_buf".to_owned(),
                    cpp_type: "void *".to_owned(),
                },
                CppParameter {
                    name: "out_buf_len".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
                CppParameter {
                    name: "pSrc_buf".to_owned(),
                    cpp_type: "const void *".to_owned(),
                },
                CppParameter {
                    name: "src_buf_len".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
            ],
            return_type: "std::size_t".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("void * pOut_buf = (void *)malloc"));
        assert!(main
            .contains("std::size_t out_buf_len = (std::size_t)(pOut_buf ? _bhf_cap_pOut_buf : 0)"));
        assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
        assert!(main.contains("std::size_t src_buf_len = (std::size_t)Size"));
        assert!(
            !main.contains("src_buf_len = bhf_bounded_length"),
            "input length must stay coherent with Data:\n{main}"
        );
        assert!(main.contains("free(pOut_buf)"));
    }

    #[test]
    fn generate_cpp_direct_harness_output_length_pointer_does_not_consume_input_pair() {
        let out = temp_dir("cpp-emit-output-length-pointer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OUT-LEN".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("compress_mem_to_heap"),
            params: vec![
                CppParameter {
                    name: "pOut_buf".to_owned(),
                    cpp_type: "void *".to_owned(),
                },
                CppParameter {
                    name: "pOut_len".to_owned(),
                    cpp_type: "std::size_t *".to_owned(),
                },
                CppParameter {
                    name: "pSrc_buf".to_owned(),
                    cpp_type: "const void *".to_owned(),
                },
                CppParameter {
                    name: "src_buf_len".to_owned(),
                    cpp_type: "std::size_t".to_owned(),
                },
            ],
            return_type: "bool".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("void * pOut_buf = (void *)malloc"));
        assert!(main.contains(
            "std::size_t _bhf_out_pOut_len = (std::size_t)(pOut_buf ? _bhf_cap_pOut_buf : 0)"
        ));
        assert!(main.contains("std::size_t *pOut_len = &_bhf_out_pOut_len"));
        assert!(main.contains("const void * pSrc_buf = (const void *)Data"));
        assert!(main.contains("std::size_t src_buf_len = (std::size_t)Size"));
        assert!(
            !main.contains("src_buf_len = bhf_bounded_length"),
            "input length must stay coherent with Data:\n{main}"
        );
        assert!(main.contains("free(pOut_buf)"));
    }

    #[test]
    fn generate_cpp_direct_harness_uses_cpp20_for_span_params() {
        let out = temp_dir("cpp-emit-span");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP005".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "bytes".to_owned(),
                cpp_type: "std::span<const std::byte>".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <span>"));
        assert!(main.contains("std::span<const std::byte> bytes("));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_uses_cpp20_for_mutable_span_params() {
        let out = temp_dir("cpp-emit-mutable-span");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP008".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "bytes".to_owned(),
                cpp_type: "std::span<std::byte>".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <span>"));
        assert!(main.contains("std::vector<std::byte> _bhf_span_storage_bytes("));
        assert!(main.contains("std::span<std::byte> bytes(_bhf_span_storage_bytes.data(), _bhf_span_storage_bytes.size())"));
        assert!(main.contains("parse(bytes);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_optional_for_optional_string() {
        let out = temp_dir("cpp-emit-optional-string");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP006".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "maybe".to_owned(),
                cpp_type: "const std::optional<std::string> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <optional>"));
        assert!(main.contains("std::optional<std::string> maybe"));
        assert!(main.contains("parse(maybe);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_optional_for_optional_scalar() {
        let out = temp_dir("cpp-emit-optional-scalar");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OPT-SCALAR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "maybe_count".to_owned(),
                cpp_type: "const std::optional<std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <optional>"));
        assert!(main.contains("std::optional<std::uint32_t> maybe_count"));
        assert!(main.contains("maybe_count.emplace(_bhf_optional_maybe_count)"));
        assert!(main.contains("parse(maybe_count);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_optional_visible_aggregate() {
        let out = temp_dir("cpp-emit-optional-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-OPT-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "maybe".to_owned(),
                cpp_type: "const std::optional<Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <optional>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::optional<Config> maybe"));
        assert!(main.contains("_bhf_optional_maybe.mode = bhf_i32(&Cur)"));
        assert!(main.contains("parse(maybe);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_vector_visible_aggregate() {
        let out = temp_dir("cpp-emit-vector-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VEC-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::vector<Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <vector>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::vector<Config> items;"));
        assert!(main.contains("_bhf_vector_items_elt.mode = bhf_i32(&Cur)"));
        assert!(main.contains("items.emplace_back(_bhf_vector_items_elt)"));
        assert!(main.contains("parse(items);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_array_visible_aggregate() {
        let out = temp_dir("cpp-emit-array-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ARRAY-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::array<Config, 2> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <array>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::array<Config, 2> items{}"));
        assert!(main.contains("_bhf_array_items_elt.mode = bhf_i32(&Cur)"));
        assert!(main.contains("items[_bhf_i_items] = _bhf_array_items_elt"));
        assert!(main.contains("parse(items);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_forward_list_visible_aggregate() {
        let out = temp_dir("cpp-emit-forward-list-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-FLIST-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::forward_list<Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <forward_list>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::forward_list<Config> items;"));
        assert!(main.contains("_bhf_forward_list_items_elt.mode = bhf_i32(&Cur)"));
        assert!(main.contains("items.emplace_front(_bhf_forward_list_items_elt)"));
        assert!(main.contains("parse(items);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_variant_visible_aggregate() {
        let out = temp_dir("cpp-emit-variant-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VARIANT-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "choice".to_owned(),
                cpp_type: "const std::variant<Config, std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <variant>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::variant<Config, std::uint32_t> choice"));
        assert!(main.contains("_bhf_variant_choice_0.mode = bhf_i32(&Cur)"));
        assert!(main.contains(
            "std::variant<Config, std::uint32_t>(std::in_place_index<0>, _bhf_variant_choice_0)"
        ));
        assert!(main.contains("parse(choice);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_unordered_map_visible_aggregate_value() {
        let out = temp_dir("cpp-emit-unordered-map-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-UMAP-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "lookup".to_owned(),
                cpp_type: "const std::unordered_map<std::string, Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <unordered_map>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::unordered_map<std::string, Config> lookup;"));
        assert!(main.contains("_bhf_unordered_map_lookup_value.mode = bhf_i32(&Cur)"));
        assert!(main.contains(
            "lookup.emplace(_bhf_unordered_map_lookup_key, _bhf_unordered_map_lookup_value)"
        ));
        assert!(main.contains("parse(lookup);"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_span_visible_aggregate() {
        let out = temp_dir("cpp-emit-span-aggregate");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SPAN-AGG".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "items".to_owned(),
                cpp_type: "const std::span<const Config> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/x.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::CTypeDefs {
                structs: vec![c_parser::CStructDef {
                    name: "Config".to_owned(),
                    fields: vec![c_parser::CParamDescriptor {
                        name: "mode".to_owned(),
                        c_type: "int".to_owned(),
                    }],
                    line: 1,
                    complete: true,
                }],
                ..Default::default()
            }],

            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <span>"));
        assert!(main.contains("#include \"x.cpp\""));
        assert!(main.contains("std::vector<Config> _bhf_span_storage_items;"));
        assert!(main.contains("_bhf_span_items_elt.mode = bhf_i32(&Cur)"));
        assert!(main.contains(
            "std::span<const Config> items(_bhf_span_storage_items.data(), _bhf_span_storage_items.size())"
        ));
        assert!(main.contains("parse(items);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
        assert!(!makefile.contains("/tmp/x.cpp"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_memory_for_smart_pointers() {
        let out = temp_dir("cpp-emit-smart-pointers");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SMART-PTR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "owned".to_owned(),
                    cpp_type: "std::unique_ptr<std::uint32_t>".to_owned(),
                },
                CppParameter {
                    name: "shared".to_owned(),
                    cpp_type: "const std::shared_ptr<std::string> &".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include <memory>"));
        assert!(main.contains("#include <utility>"));
        assert!(main.contains("std::unique_ptr<std::uint32_t> owned = std::make_unique"));
        assert!(main.contains("std::shared_ptr<std::string> shared = std::make_shared"));
        assert!(main.contains("parse(std::move(owned), shared);"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_utility_for_pair() {
        let out = temp_dir("cpp-emit-pair");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-PAIR".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "entry".to_owned(),
                cpp_type: "const std::pair<std::uint32_t, std::string_view> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <utility>"));
        assert!(main.contains("std::pair<std::uint32_t, std::string_view> entry"));
        assert!(main.contains("parse(entry);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_tuple_for_tuple() {
        let out = temp_dir("cpp-emit-tuple");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-TUPLE".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "entry".to_owned(),
                cpp_type: "const std::tuple<std::uint32_t, std::string_view, bool> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <tuple>"));
        assert!(main.contains("std::tuple<std::uint32_t, std::string_view, bool> entry"));
        assert!(main.contains("parse(entry);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_variant_for_variant() {
        let out = temp_dir("cpp-emit-variant");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VARIANT".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "choice".to_owned(),
                cpp_type: "const std::variant<std::uint32_t, std::string_view, bool> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <variant>"));
        assert!(main.contains("std::variant<std::uint32_t, std::string_view, bool> choice"));
        assert!(main.contains("std::in_place_index<1>"));
        assert!(main.contains("parse(choice);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    /// Plain clang++ (no `--gcc-install-dir` plumbing) can link a trivial
    /// `-fsanitize=fuzzer` C++ program. Gates the C++ libFuzzer e2e so a box
    /// without the fuzzer runtime (or needing gcc-install-dir flags) skips it.
    fn cpp_libfuzzer_toolchain_available() -> bool {
        if clangxx_compile_flags("libfuzzer-probe") != Some(Vec::new()) {
            return false;
        }
        let smoke = std::env::temp_dir().join(format!("bhf-cpp-lf-smoke-{}", std::process::id()));
        if fs::create_dir_all(&smoke).is_err() {
            return false;
        }
        let src = smoke.join("s.cpp");
        let wrote = fs::write(
            &src,
            "#include <cstddef>\n#include <cstdint>\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s){(void)d;(void)s;return 0;}\n",
        );
        let ok = wrote.is_ok()
            && Command::new("clang++")
                .args(["-fsanitize=fuzzer,address", "-O1", "-std=c++17", "-o"])
                .arg(smoke.join("s"))
                .arg(&src)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
        fs::remove_dir_all(&smoke).ok();
        ok
    }

    /// Generate and `make main` a C++ harness for `args`, or `None` (skipping)
    /// when clang++, its C++ headers or make are missing.
    fn build_cpp_harness(args: GenerateCppDirectArgs) -> Option<PathBuf> {
        let make_ok = Command::new("make")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !make_ok || clangxx_compile_flags("cpp-trace").is_none_or(|flags| !flags.is_empty()) {
            eprintln!(
                "skipping {} build: clang++/make unavailable",
                args.harness_id
            );
            return None;
        }
        let out = args.output_dir.clone();
        generate_cpp_direct_harness(args).unwrap();
        let build = Command::new("make")
            .arg("main")
            .current_dir(&out)
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make main failed:\n{}\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr),
            fs::read_to_string(out.join("main.cpp")).unwrap_or_default()
        );
        Some(out)
    }

    /// The traced source must not add a warning a `-Werror` build fails on.
    fn assert_cpp_compiles_warning_free(out: &Path) {
        let check = Command::new("clang++")
            .args(["-std=c++17", "-fsyntax-only", "-Wall", "-Wextra", "-Werror"])
            .arg("-I")
            .arg(runtime_dir())
            .arg("-I")
            .arg(out)
            .arg(out.join("main.cpp"))
            .output()
            .expect("run clang++");
        assert!(
            check.status.success(),
            "warnings in the generated harness:\n{}",
            String::from_utf8_lossy(&check.stderr)
        );
    }

    /// Run a built harness on `input` with BHF_TRACE_ARGS=1 and return its
    /// `BHF_ARG` lines as JSON.
    fn cpp_traced_args(out: &Path, input: &[u8]) -> Vec<serde_json::Value> {
        let path = out.join("traced-input.bin");
        fs::write(&path, input).unwrap();
        let run = Command::new(out.join("main"))
            .arg(&path)
            .env("BHF_TRACE_ARGS", "1")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&run.stderr);
        assert!(run.status.success(), "harness failed:\n{stderr}");
        stderr
            .lines()
            .filter_map(|line| line.strip_prefix("BHF_ARG "))
            .map(|json| serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}: {json}")))
            .collect()
    }

    fn cpp_traced<'a>(
        args: &'a [serde_json::Value],
        name: &str,
        phase: Option<&str>,
    ) -> &'a serde_json::Value {
        args.iter()
            .find(|arg| arg["name"] == name && arg.get("phase").and_then(|p| p.as_str()) == phase)
            .unwrap_or_else(|| panic!("no {name} ({phase:?}) line in {args:#?}"))
    }

    /// With BHF_TRACE_ARGS=1 a built C++ method harness prints the receiver's
    /// constructor argument and the constructed receiver, a length-prefixed
    /// string, and an in-out reference before and after the call.
    #[test]
    fn built_cpp_harness_traces_receiver_and_reference_arguments() {
        let out = temp_dir("cpp-trace-receiver");
        fs::write(
            out.join("widget.hpp"),
            "#pragma once\n\
             class Widget {\n\
             public:\n\
             \x20   explicit Widget(int mode) : mode_(mode) {}\n\
             \x20   unsigned int read(const char *buffer, unsigned short &offset) {\n\
             \x20       offset = (unsigned short)(offset + 1);\n\
             \x20       return (unsigned int)(buffer[0] + mode_);\n\
             \x20   }\n\
             private:\n\
             \x20   int mode_;\n\
             };\n",
        )
        .unwrap();
        let mut target = cppfunction("read");
        target.qualifier_path = vec!["Widget".to_owned()];
        target.api.is_method = true;
        target.api.class_name = Some("Widget".to_owned());
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-TRACE".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("widget.hpp"),
            target,
            params: vec![
                CppParameter {
                    name: "buffer".to_owned(),
                    cpp_type: "const char *".to_owned(),
                },
                CppParameter {
                    name: "offset".to_owned(),
                    cpp_type: "unsigned short &".to_owned(),
                },
            ],
            return_type: "unsigned int".to_owned(),
            target_includes: vec!["widget.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "int".to_owned(),
            }],
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let input = [3, 0, b'A', b'B', b'C', 5, 0, 0, 0, 2, 0, 0, 0];
        let args = cpp_traced_args(&out, &input);

        let buffer = cpp_traced(&args, "buffer", None);
        assert_eq!(buffer["call"], "target");
        assert_eq!(buffer["span"], serde_json::json!([0, 5]));
        assert_eq!(buffer["len"], 3);
        assert_eq!(buffer["alloc_size"], 4);
        assert_eq!(buffer["preview_hex"], "414243");
        let offset = cpp_traced(&args, "offset", None);
        assert_eq!(offset["role"], "out");
        assert_eq!(offset["value"], "5");
        assert_eq!(offset["span"], serde_json::json!([5, 9]));
        assert_eq!(cpp_traced(&args, "offset", Some("after"))["value"], "6");

        let mode = cpp_traced(&args, "mode", None);
        assert_eq!(mode["call"], "receiver");
        assert_eq!(mode["role"], "receiver");
        assert_eq!(mode["value"], "2");
        assert_eq!(mode["span"], serde_json::json!([9, 13]));
        let receiver = cpp_traced(&args, "this", None);
        assert_eq!(receiver["role"], "receiver");
        assert_eq!(receiver["type"], "Widget");
        assert_eq!(receiver["decoder"], "constructor(1 decoded argument(s))");
        fs::remove_dir_all(&out).ok();
    }

    /// A C++ method harness's layout lists the target's cursor parameters,
    /// then the receiver's constructor arguments, then where the target's
    /// whole-input parameter takes the bytes left, and replays like the trace.
    #[test]
    fn cpp_receiver_harness_layout_matches_its_argument_trace() {
        let out = temp_dir("cpp-layout-receiver");
        fs::write(
            out.join("widget.hpp"),
            "#pragma once\n\
             #include <string>\n\
             class Widget {\n\
             public:\n\
             \x20   explicit Widget(int mode) : mode_(mode) {}\n\
             \x20   int load(const unsigned char *body, size_t len, unsigned short tag) {\n\
             \x20       return (int)len + (len ? body[0] : 0) + tag + mode_;\n\
             \x20   }\n\
             private:\n\
             \x20   int mode_;\n\
             };\n",
        )
        .unwrap();
        let mut target = cppfunction("load");
        target.qualifier_path = vec!["Widget".to_owned()];
        target.api.is_method = true;
        target.api.class_name = Some("Widget".to_owned());
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-LAYOUT".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("widget.hpp"),
            target,
            params: vec![
                CppParameter {
                    name: "body".to_owned(),
                    cpp_type: "const unsigned char *".to_owned(),
                },
                CppParameter {
                    name: "len".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
                CppParameter {
                    name: "tag".to_owned(),
                    cpp_type: "unsigned short".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["widget.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "int".to_owned(),
            }],
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        generate_cpp_direct_harness(args.clone()).unwrap();
        let layout = crate::arg_layout::ArgLayout::read(&out).unwrap().unwrap();
        assert_eq!(layout.language, "cpp");
        let order: Vec<String> = layout
            .steps
            .iter()
            .map(|step| match step {
                crate::arg_layout::LayoutStep::Param(p) => format!("{}.{}", p.call, p.name),
                crate::arg_layout::LayoutStep::Remainder { call, .. } => format!("rest:{call}"),
                crate::arg_layout::LayoutStep::Opaque { what } => what.clone(),
            })
            .collect();
        assert_eq!(
            order,
            [
                "target.tag",
                "receiver.mode",
                "rest:target",
                "target.body",
                "target.len"
            ]
        );
        let body = layout.params().find(|p| p.name == "body").unwrap();
        assert_eq!(body.paired_with.as_deref(), Some("len"));
        let input = [7u8, 0, 0, 0, 2, 0, 0, 0, b'x', b'y', b'z'];
        let decoded = layout.decode(&input);
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        let traced = cpp_traced_args(&out, &input);
        for name in ["tag", "mode", "body", "len"] {
            let trace = cpp_traced(&traced, name, None);
            let stat = decoded.iter().find(|a| a.name == name).unwrap();
            assert!(stat.decoded, "{stat:?}");
            assert_eq!(
                serde_json::json!(stat.span),
                trace["span"],
                "{name}: static {stat:?} vs traced {trace}"
            );
            if let Some(value) = &stat.value {
                assert_eq!(trace["value"], serde_json::json!(value), "{name}");
            } else {
                assert_eq!(trace["len"], serde_json::json!(stat.len), "{name}");
            }
        }
        fs::remove_dir_all(&out).ok();
    }

    fn cpp_args_for(
        out: &Path,
        harness_id: &str,
        target: CppFunction,
        params: &[(&str, &str)],
        constructor_params: &[(&str, &str)],
        header: &str,
    ) -> GenerateCppDirectArgs {
        fs::write(out.join("widget.hpp"), header).unwrap();
        let to_params = |params: &[(&str, &str)]| {
            params
                .iter()
                .map(|(name, ty)| CppParameter {
                    name: (*name).to_owned(),
                    cpp_type: (*ty).to_owned(),
                })
                .collect::<Vec<_>>()
        };
        GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: harness_id.to_owned(),
            output_dir: out.to_path_buf(),
            source_path: out.join("widget.hpp"),
            target,
            params: to_params(params),
            return_type: "int".to_owned(),
            target_includes: vec!["widget.hpp".to_owned()],
            target_includes_dirs: vec![out.to_path_buf()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: to_params(constructor_params),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        }
    }

    /// In the C++ lane too, a `(buffer, length)` pair takes the bytes after
    /// the scalars decoded with it, and a method's buffer the bytes after its
    /// receiver's constructor arguments: no input byte feeds two parameters.
    #[test]
    fn built_cpp_harnesses_never_share_bytes_between_a_buffer_and_scalars() {
        let out = temp_dir("cpp-layout-free");
        let args = cpp_args_for(
            &out,
            "H-CPP-LAYOUT",
            cppfunction("widget_parse"),
            &[
                ("data", "const unsigned char *"),
                ("len", "size_t"),
                ("mode", "int"),
            ],
            &[],
            "#pragma once\n#include <cstddef>\n\
             inline int widget_parse(const unsigned char *data, std::size_t len, int mode) {\n\
             \x20   return len ? data[0] + mode : mode;\n\
             }\n",
        );
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[3, 0, 0, 0, 0x11, 0x22]);
        let mode = cpp_traced(&args, "mode", None);
        assert_eq!(mode["value"], "3");
        assert_eq!(mode["span"], serde_json::json!([0, 4]));
        let data = cpp_traced(&args, "data", None);
        assert_eq!(data["span"], serde_json::json!([4, 6]));
        assert_eq!(data["preview_hex"], "1122");
        assert_eq!(cpp_traced(&args, "len", None)["value"], "2");
        fs::remove_dir_all(&out).ok();

        let out = temp_dir("cpp-layout-receiver");
        let mut target = cppfunction("feed");
        target.qualifier_path = vec!["Widget".to_owned()];
        target.api.is_method = true;
        target.api.class_name = Some("Widget".to_owned());
        let args = cpp_args_for(
            &out,
            "H-CPP-LAYOUT-RECV",
            target,
            &[("buf", "const unsigned char *"), ("len", "size_t")],
            &[("mode", "int")],
            "#pragma once\n#include <cstddef>\n\
             class Widget {\n\
             public:\n\
             \x20   explicit Widget(int mode) : mode_(mode) {}\n\
             \x20   int feed(const unsigned char *buf, std::size_t len) {\n\
             \x20       return len ? buf[0] + mode_ : mode_;\n\
             \x20   }\n\
             private:\n\
             \x20   int mode_;\n\
             };\n",
        );
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[5, 0, 0, 0, 0x33, 0x44, 0x55]);
        let mode = cpp_traced(&args, "mode", None);
        assert_eq!(mode["call"], "receiver");
        assert_eq!(mode["value"], "5");
        assert_eq!(mode["span"], serde_json::json!([0, 4]));
        let buf = cpp_traced(&args, "buf", None);
        assert_eq!(buf["span"], serde_json::json!([4, 7]));
        assert_eq!(buf["preview_hex"], "334455");
        assert_eq!(cpp_traced(&args, "len", None)["value"], "3");
        fs::remove_dir_all(&out).ok();
    }

    fn cpp_method(class: &str, method: &str) -> CppFunction {
        let mut target = cppfunction(method);
        target.qualifier_path = vec![class.to_owned()];
        target.api.is_method = true;
        target.api.class_name = Some(class.to_owned());
        target
    }

    /// The trace builds for any receiver and argument type: a receiver whose
    /// `get()` returns a value rather than a pointer, one whose `data()`
    /// returns `const void *`, and a pointer to `volatile` storage. Such a
    /// receiver is shown as its object bytes.
    #[test]
    fn built_cpp_harness_traces_receivers_and_pointers_of_any_shape() {
        let out = temp_dir("cpp-trace-get");
        let args = cpp_args_for(
            &out,
            "H-CPP-TRACE-GET",
            cpp_method("Counter", "bump"),
            &[("by", "int")],
            &[],
            "#pragma once\n\
             class Counter {\n\
             public:\n\
             \x20   Counter() : n_(0) {}\n\
             \x20   int get() const { return n_; }\n\
             \x20   int bump(int by) { n_ += by; return n_; }\n\
             private:\n\
             \x20   int n_;\n\
             };\n",
        );
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[2, 0, 0, 0]);
        assert_eq!(cpp_traced(&args, "by", None)["value"], "2");
        let receiver = cpp_traced(&args, "this", None);
        assert_eq!(receiver["len"], 4);
        assert_eq!(receiver["preview_hex"], "00000000");
        fs::remove_dir_all(&out).ok();

        let out = temp_dir("cpp-trace-void-data");
        let args = cpp_args_for(
            &out,
            "H-CPP-TRACE-VOID-DATA",
            cpp_method("Blob", "poke"),
            &[("by", "int")],
            &[],
            "#pragma once\n#include <cstddef>\n\
             class Blob {\n\
             public:\n\
             \x20   Blob() : n_(0) {}\n\
             \x20   const void *data() const { return &n_; }\n\
             \x20   std::size_t size() const { return sizeof n_; }\n\
             \x20   int poke(int by) { n_ += by; return n_; }\n\
             private:\n\
             \x20   int n_;\n\
             };\n",
        );
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[3, 0, 0, 0]);
        assert_eq!(cpp_traced(&args, "by", None)["value"], "3");
        assert_eq!(cpp_traced(&args, "this", None)["len"], 4);
        fs::remove_dir_all(&out).ok();

        let out = temp_dir("cpp-trace-volatile");
        let args = cpp_args_for(
            &out,
            "H-CPP-TRACE-VOLATILE",
            cppfunction("widget_poke"),
            &[("reg", "volatile unsigned int *"), ("value", "int")],
            &[],
            "#pragma once\n\
             inline int widget_poke(volatile unsigned int *reg, int value) {\n\
             \x20   *reg = (unsigned int)value;\n\
             \x20   return value;\n\
             }\n",
        );
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[9, 0, 0, 0, 4, 0, 0, 0]);
        assert!(cpp_traced(&args, "reg", None)["ptr"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        fs::remove_dir_all(&out).ok();
    }

    /// `bhf_trace_value` compiles warning-free for every argument shape a
    /// harness can pass (accessors that only look like a container or a smart
    /// pointer, cv-qualified pointers, incomplete pointees, overloaded `&`),
    /// with clang++ and g++, and under clang it needs no library trait that
    /// an older libstdc++ lacks.
    #[test]
    fn the_cpp_trace_dispatch_compiles_for_any_argument_shape() {
        let tu = "#include <cstddef>\n#include <cstdint>\n#include <memory>\n#include <string>\n\
                  #include <vector>\n#include \"bhf_trace.h\"\n\
                  struct Counter { int n; int get() const { return n; } };\n\
                  struct Ref { int n; int &get() { return n; } const int &get() const { return n; } };\n\
                  struct Blob { int n; const void *data() const { return &n; } std::size_t size() const { return 4; } };\n\
                  struct Impl;\n\
                  struct Handle { Impl *p; Impl *data() const { return p; } int size() const { return 0; } Impl *get() const { return p; } };\n\
                  struct Odd { int n; void size() const {} const int *data() const { return &n; } };\n\
                  struct Amp { int n; Amp *operator&() { return 0; } const Amp *operator&() const { return 0; } };\n\
                  struct Owned { std::string s; };\n\
                  enum Mode { MODE_A = 1 };\n\
                  enum class Wide : unsigned short { X = 2 };\n\
                  typedef int (*Fn)(int);\n\
                  int main() {\n\
                  \x20   const uint8_t d[4] = {1, 2, 3, 4};\n\
                  \x20   volatile unsigned int reg = 5; volatile unsigned int *preg = &reg;\n\
                  \x20   const volatile Mode vm = MODE_A; const volatile Mode *pvm = &vm;\n\
                  \x20   volatile char vc[2] = {'a', 0}; volatile char *pvc = vc;\n\
                  \x20   volatile void *vv = preg; Fn fn = 0; int arr[3] = {1, 2, 3};\n\
                  \x20   Counter c = {1}; Ref r = {2}; Blob b = {3}; Handle h = {0}; Odd o = {4}; Amp a = {5};\n\
                  \x20   Owned w; std::vector<int> v(2, 7); std::unique_ptr<int> u(new int(9));\n\
                  \x20   std::shared_ptr<Impl> si; Wide wide = Wide::X; volatile int vi = 6;\n\
                  \x20   bhf_tl_begin(\"{\");\n\
                  \x20   bhf_trace_value(preg, d, 4, BHF_TRACE_NO_LEN, BHF_TRACE_DEREF);\n\
                  \x20   bhf_trace_value(pvm, d, 4, BHF_TRACE_NO_LEN, BHF_TRACE_DEREF);\n\
                  \x20   bhf_trace_value(pvc, d, 4, BHF_TRACE_NO_LEN, BHF_TRACE_NUL);\n\
                  \x20   bhf_trace_value(vv, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(fn, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(arr, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(c, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(r, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(b, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(h, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(o, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(a, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(w, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(v, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(u, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(si, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(wide, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(vi, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_trace_value(nullptr, d, 4, BHF_TRACE_NO_LEN, 0);\n\
                  \x20   bhf_tl_end();\n\
                  \x20   return 0;\n\
                  }\n";
        let dir = temp_dir("cpp-trace-shapes");
        let source = dir.join("shapes.cpp");
        fs::write(&source, tu).unwrap();
        let mut compiled = 0;
        for compiler in ["clang++", "g++"] {
            if !Command::new(compiler)
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                continue;
            }
            for std in ["-std=c++11", "-std=c++17"] {
                let out = Command::new(compiler)
                    .args([std, "-fsyntax-only", "-Wall", "-Wextra", "-Werror"])
                    .arg("-I")
                    .arg(runtime_dir())
                    .arg(&source)
                    .output()
                    .expect("run the C++ compiler");
                assert!(
                    out.status.success(),
                    "{compiler} {std}:\n{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                compiled += 1;
            }
        }
        if compiled > 0
            && Command::new("clang++")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        {
            let expanded = Command::new("clang++")
                .args(["-std=c++11", "-E", "-P", "-x", "c++"])
                .arg("-I")
                .arg(runtime_dir())
                .arg(runtime_dir().join("bhf_trace.h"))
                .output()
                .expect("run clang++ -E");
            let expanded = String::from_utf8_lossy(&expanded.stdout);
            let trace_part = &expanded[expanded.find("namespace bhf_trace_detail").unwrap()..];
            assert!(
                !trace_part.contains("is_trivially_copyable<"),
                "the trace uses the library trait under clang"
            );
            assert!(trace_part.contains("__is_trivially_copyable("));
        }
        fs::remove_dir_all(&dir).ok();
    }

    /// A struct whose fields are named like the harness's `Data` and `Size`
    /// is decoded from the cursor in the C++ lane too, and the harness builds.
    #[test]
    fn built_cpp_harness_decodes_a_struct_with_fields_named_like_the_input() {
        let out = temp_dir("cpp-struct-size-field");
        let header = "#pragma once\n\
                      typedef struct widget_hdr { unsigned int Size; unsigned int Data; } widget_hdr;\n\
                      inline int widget_check(const widget_hdr *hdr, int level) {\n\
                      \x20   return (int)(hdr->Size + hdr->Data) + level;\n\
                      }\n";
        let mut args = cpp_args_for(
            &out,
            "H-CPP-STRUCT-SIZE",
            cppfunction("widget_check"),
            &[("hdr", "const widget_hdr *"), ("level", "int")],
            &[],
            header,
        );
        args.type_defs = vec![c_parser::parse_c_type_defs(
            "typedef struct widget_hdr { unsigned int Size; unsigned int Data; } widget_hdr;",
        )
        .unwrap()];
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
        assert_eq!(
            cpp_traced(&args, "hdr", None)["span"],
            serde_json::json!([0, 8])
        );
        let level = cpp_traced(&args, "level", None);
        assert_eq!(level["value"], "3");
        assert_eq!(level["span"], serde_json::json!([8, 12]));
        fs::remove_dir_all(&out).ok();
    }

    /// A receiver whose constructor takes only a whole-input argument gets the
    /// bytes the method's scalars left, not the whole input again.
    #[test]
    fn built_cpp_harness_gives_constructor_input_the_bytes_after_the_target_scalars() {
        let out = temp_dir("cpp-ctor-input");
        let args = cpp_args_for(
            &out,
            "H-CPP-CTOR-INPUT",
            cpp_method("Widget", "scan"),
            &[("bit_index", "unsigned int")],
            &[("blob", "std::vector<std::uint8_t>")],
            "#pragma once\n#include <cstdint>\n#include <vector>\n\
             class Widget {\n\
             public:\n\
             \x20   explicit Widget(std::vector<std::uint8_t> blob) : blob_(blob) {}\n\
             \x20   int scan(unsigned int bit_index) {\n\
             \x20       return blob_.empty() ? 0 : blob_[0] + (int)(bit_index & 1u);\n\
             \x20   }\n\
             private:\n\
             \x20   std::vector<std::uint8_t> blob_;\n\
             };\n",
        );
        let Some(out) = build_cpp_harness(args) else {
            return;
        };
        assert_cpp_compiles_warning_free(&out);
        let args = cpp_traced_args(&out, &[7, 0, 0, 0, 0xaa]);
        let bit_index = cpp_traced(&args, "bit_index", None);
        assert_eq!(bit_index["value"], "7");
        assert_eq!(bit_index["span"], serde_json::json!([0, 4]));
        let blob = cpp_traced(&args, "blob", None);
        assert_eq!(blob["call"], "receiver");
        assert_eq!(blob["span"], serde_json::json!([4, 5]));
        assert_eq!(blob["preview_hex"], "aa");
        fs::remove_dir_all(&out).ok();
    }

    /// End-to-end proof of the portable C++ libFuzzer target (#62): the C++
    /// recipe compiles the C shim `-x c` into its own object and links it (with
    /// `extern "C"` `bhf_run_one`) into a real libFuzzer binary that ASan-crashes
    /// on a bad input, without bhf's fork-server driver.
    #[test]
    fn make_libfuzzer_builds_a_working_cpp_libfuzzer_binary() {
        if !cpp_libfuzzer_toolchain_available() {
            eprintln!("skipping C++ make_libfuzzer e2e: clang++/libFuzzer unavailable");
            return;
        }
        let out = temp_dir("cpp-libfuzzer-e2e");
        let runtime = runtime_dir();
        let target_cpp = out.join("target.cpp");
        fs::write(
            &target_cpp,
            "#include <stddef.h>\n#include <stdint.h>\n\
             int parse(const uint8_t *data, size_t size) {\n\
             \x20   if (size >= 4 && data[0]=='F' && data[1]=='U' && data[2]=='Z' && data[3]=='Z') {\n\
             \x20       volatile int *p = nullptr; *p = 1;\n\
             \x20   }\n\
             \x20   return 0;\n\
             }\n",
        )
        .unwrap();
        fs::write(
            out.join("target.hpp"),
            "#include <stddef.h>\n#include <stdint.h>\nint parse(const uint8_t *, size_t);\n",
        )
        .unwrap();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-LF-E2E".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("target.hpp"),
            target: cppfunction("parse"),
            params: vec![
                CppParameter {
                    name: "data".to_owned(),
                    cpp_type: "const uint8_t *".to_owned(),
                },
                CppParameter {
                    name: "size".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["target.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: vec![target_cpp.clone()],
            compile_flags: Vec::new(),
            c_runtime_include: runtime,
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        generate_cpp_direct_harness(args).unwrap();
        assert!(out.join("bhf_libfuzzer.c").is_file());
        assert!(out.join("Mayhemfile").is_file());
        assert!(out.join("PORTABILITY.md").is_file());

        let build = Command::new("make")
            .arg("libfuzzer")
            .current_dir(&out)
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make libfuzzer failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        let bin = out.join("main_libfuzzer");
        assert!(bin.is_file(), "main_libfuzzer not produced");

        let ok = out.join("ok.bin");
        fs::write(&ok, b"hi").unwrap();
        assert!(
            Command::new(&bin)
                .arg(&ok)
                .output()
                .unwrap()
                .status
                .success(),
            "clean input must not crash"
        );
        let crash = out.join("crash.bin");
        fs::write(&crash, b"FUZZ....").unwrap();
        let r = Command::new(&bin).arg(&crash).output().unwrap();
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(
            !r.status.success(),
            "magic input must crash, stderr:\n{err}"
        );
        assert!(
            err.contains("AddressSanitizer") || err.contains("ERROR") || err.contains("SUMMARY"),
            "expected an ASan/libFuzzer crash report, got:\n{err}"
        );
        fs::remove_dir_all(&out).ok();
    }

    /// A harness around the project's own `LLVMFuzzerTestOneInput` builds its
    /// portable libFuzzer binary from the project sources alone: no shim (which
    /// would define the entry point a second time) and no `main.cpp` (whose
    /// `bhf_run_one` forwards into that same entry point).
    #[test]
    fn make_libfuzzer_links_a_passthrough_entrypoint_directly() {
        if !cpp_libfuzzer_toolchain_available() {
            eprintln!("skipping C++ passthrough make_libfuzzer e2e: clang++/libFuzzer unavailable");
            return;
        }
        let out = temp_dir("cpp-passthrough-libfuzzer");
        let driver = out.join("drive_codec.cpp");
        fs::write(
            &driver,
            "#include <cstddef>\n#include <cstdint>\n\
             static int decode_record(const uint8_t *data, size_t size) {\n\
             \x20   if (size >= 4 && data[0]=='F' && data[1]=='U' && data[2]=='Z' && data[3]=='Z') {\n\
             \x20       volatile int *p = nullptr; *p = 1;\n\
             \x20   }\n\
             \x20   return 0;\n\
             }\n\
             extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
             \x20   return decode_record(data, size);\n\
             }\n",
        )
        .unwrap();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-PASSTHROUGH-LF".to_owned(),
            output_dir: out.clone(),
            source_path: driver.clone(),
            target: cppfunction("LLVMFuzzerTestOneInput"),
            params: vec![
                CppParameter {
                    name: "data".to_owned(),
                    cpp_type: "const uint8_t *".to_owned(),
                },
                CppParameter {
                    name: "size".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: vec![out.clone()],
            target_sources: vec![driver.clone()],
            compile_flags: Vec::new(),
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        generate_cpp_direct_harness(args).unwrap();
        assert!(
            !out.join("bhf_libfuzzer.c").exists(),
            "no shim for a passthrough"
        );
        let doc = fs::read_to_string(out.join("PORTABILITY.md")).unwrap();
        assert!(doc.contains("hfuzz-clang++"), "{doc}");
        assert!(!doc.contains(" main.c "), "{doc}");

        let build = Command::new("make")
            .arg("libfuzzer")
            .current_dir(&out)
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make libfuzzer failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        let bin = out.join("main_libfuzzer");
        let ok = out.join("ok.bin");
        fs::write(&ok, b"hi").unwrap();
        let clean = Command::new(&bin).arg(&ok).output().unwrap();
        assert!(
            clean.status.success(),
            "clean input must run once and exit: {}",
            String::from_utf8_lossy(&clean.stderr)
        );
        let crash = out.join("crash.bin");
        fs::write(&crash, b"FUZZ....").unwrap();
        let r = Command::new(&bin).arg(&crash).output().unwrap();
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(
            !r.status.success(),
            "magic input must crash, stderr:\n{err}"
        );
        assert!(err.contains("AddressSanitizer"), "{err}");
        fs::remove_dir_all(&out).ok();
    }

    /// A C++ source tree, include dir and runtime dir whose paths contain spaces,
    /// parentheses and an apostrophe must generate, build and run.
    #[test]
    fn cpp_harness_builds_from_paths_with_spaces() {
        let Some(cxx_flags) = clangxx_compile_flags("cpp-spaced-paths") else {
            eprintln!("skipping spaced-path e2e: clang++ C++ headers unavailable");
            return;
        };
        if !Command::new("make")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            eprintln!("skipping spaced-path e2e: make unavailable");
            return;
        }
        let root = temp_dir("cpp spaced paths");
        let src_dir = root.join("My Proj (copy)/src lib");
        let inc_dir = root.join("My Proj (copy)/include dir");
        let runtime = root.join("tool's runtime/c_runtime");
        let out = root.join("work dir/harnesses/H-CPP-SPACED");
        fs::create_dir_all(&src_dir).unwrap();
        fs::create_dir_all(&inc_dir).unwrap();
        fs::create_dir_all(&runtime).unwrap();
        for entry in fs::read_dir(runtime_dir()).unwrap().flatten() {
            if entry.path().is_file() {
                fs::copy(entry.path(), runtime.join(entry.file_name())).unwrap();
            }
        }
        fs::write(
            inc_dir.join("record.hpp"),
            "#include <stddef.h>\nnamespace demo {\nint last_byte(const unsigned char *data, size_t len);\n}\n",
        )
        .unwrap();
        let source = src_dir.join("record.cpp");
        fs::write(
            &source,
            "#include \"record.hpp\"\n\
             namespace demo {\n\
             int last_byte(const unsigned char *data, size_t len) { return len ? data[len - 1] : 0; }\n\
             }\n",
        )
        .unwrap();
        let mut target = cppfunction("last_byte");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-SPACED".to_owned(),
            output_dir: out.clone(),
            source_path: inc_dir.join("record.hpp"),
            target,
            params: vec![
                CppParameter {
                    name: "data".to_owned(),
                    cpp_type: "const unsigned char *".to_owned(),
                },
                CppParameter {
                    name: "len".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["record.hpp".to_owned()],
            target_includes_dirs: vec![inc_dir.clone()],
            target_sources: vec![source.clone()],
            compile_flags: cxx_flags,
            c_runtime_include: runtime,
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        generate_cpp_direct_harness(args).expect("spaced paths are accepted");
        let makefile = fs::read_to_string(out.join("Makefile")).unwrap();
        assert!(
            makefile.contains(&format!("-iquote \"{}\"", inc_dir.display()))
                && makefile.contains(&format!(" \"{}\"", source.display())),
            "spaced paths must be double-quoted in the Makefile:\n{makefile}"
        );
        let build = Command::new("make")
            .arg("main")
            .current_dir(&out)
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make main failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        let input = out.join("input.bin");
        fs::write(&input, b"record").unwrap();
        let run = Command::new(out.join("main")).arg(&input).output().unwrap();
        assert!(
            run.status.success(),
            "{}",
            String::from_utf8_lossy(&run.stderr)
        );
        fs::remove_dir_all(&root).ok();
    }

    /// A correct function over a typedef'd `(buffer, length)` pair must not crash
    /// under the generated harness. Unpaired, the harness handed it an
    /// independent fuzzed length larger than the buffer it copied, and ASan
    /// reported a heap-buffer-overflow the harness itself caused.
    #[test]
    fn built_cpp_harness_keeps_a_typedef_buffer_and_its_length_coherent() {
        let Some(cxx_flags) = clangxx_compile_flags("cpp-typedef-pair") else {
            eprintln!("skipping typedef pair e2e: clang++ C++ headers unavailable");
            return;
        };
        if !Command::new("make")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            eprintln!("skipping typedef pair e2e: make unavailable");
            return;
        }
        let out = temp_dir("cpp-typedef-pair-e2e");
        let header = "#include <stddef.h>\n\
                      typedef unsigned char u8_t;\n\
                      namespace demo {\n\
                      int last_byte(const u8_t *buf, size_t len);\n\
                      }\n";
        fs::write(out.join("record.hpp"), header).unwrap();
        let target_cpp = out.join("record.cpp");
        fs::write(
            &target_cpp,
            "#include \"record.hpp\"\n\
             namespace demo {\n\
             int last_byte(const u8_t *buf, size_t len) { return len ? buf[len - 1] : 0; }\n\
             }\n",
        )
        .unwrap();
        let mut target = cppfunction("last_byte");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-TYPEDEF-PAIR".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("record.hpp"),
            target,
            params: vec![
                CppParameter {
                    name: "buf".to_owned(),
                    cpp_type: "const u8_t *".to_owned(),
                },
                CppParameter {
                    name: "len".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["record.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: vec![target_cpp],
            compile_flags: cxx_flags,
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::parse_c_type_defs(header).unwrap()],
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        generate_cpp_direct_harness(args).unwrap();
        let build = Command::new("make")
            .arg("main")
            .current_dir(&out)
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make main failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        // Read as a little-endian length these bytes are 4096: far past the end of
        // a 12-byte buffer if the length were decoded on its own.
        let input = out.join("input.bin");
        fs::write(&input, [0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let run = Command::new(out.join("main")).arg(&input).output().unwrap();
        assert!(
            run.status.success(),
            "a correct function must not crash under its harness:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        fs::remove_dir_all(&out).ok();
    }

    /// The same for a buffer spelled through a pointer typedef (`LPCBYTE`): it
    /// used to get one byte of storage while its length was fuzzed up to
    /// 0x7fffffff, so a correct checksum loop overflowed the harness's stack.
    #[test]
    fn built_cpp_harness_keeps_a_pointer_typedef_buffer_and_its_length_coherent() {
        let Some(cxx_flags) = clangxx_compile_flags("cpp-ptr-typedef-pair") else {
            eprintln!("skipping pointer typedef pair e2e: clang++ C++ headers unavailable");
            return;
        };
        if !Command::new("make")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            eprintln!("skipping pointer typedef pair e2e: make unavailable");
            return;
        }
        let out = temp_dir("cpp-ptr-typedef-pair-e2e");
        let header = "typedef unsigned char BYTE;\n\
                      typedef const BYTE *LPCBYTE;\n\
                      typedef unsigned long DWORD;\n\
                      namespace demo {\n\
                      int checksum(LPCBYTE pbData, DWORD cbData);\n\
                      }\n";
        fs::write(out.join("sum.hpp"), header).unwrap();
        let target_cpp = out.join("sum.cpp");
        fs::write(
            &target_cpp,
            "#include \"sum.hpp\"\n\
             namespace demo {\n\
             int checksum(LPCBYTE pbData, DWORD cbData) {\n\
             \x20 int s = 0;\n\
             \x20 for (DWORD i = 0; i < cbData; i++) s += pbData[i];\n\
             \x20 return s;\n\
             }\n\
             }\n",
        )
        .unwrap();
        let mut target = cppfunction("checksum");
        target.qualifier_path = vec!["demo".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-PTR-TYPEDEF-PAIR".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("sum.hpp"),
            target,
            params: vec![
                CppParameter {
                    name: "pbData".to_owned(),
                    cpp_type: "LPCBYTE".to_owned(),
                },
                CppParameter {
                    name: "cbData".to_owned(),
                    cpp_type: "DWORD".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: vec!["sum.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: vec![target_cpp],
            compile_flags: cxx_flags,
            c_runtime_include: runtime_dir(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![c_parser::parse_c_type_defs(header).unwrap()],
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        generate_cpp_direct_harness(args).unwrap();
        let build = Command::new("make")
            .arg("main")
            .current_dir(&out)
            .output()
            .expect("run make");
        assert!(
            build.status.success(),
            "make main failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );
        // Decoded on its own, the length read from these bytes is about 1 MiB.
        let input = out.join("input.bin");
        fs::write(&input, [b'A', 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let run = Command::new(out.join("main")).arg(&input).output().unwrap();
        assert!(
            run.status.success(),
            "a correct function must not crash under its harness:\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
        fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_variant_monostate_alternative() {
        let out = temp_dir("cpp-emit-variant-monostate");
        let runtime = runtime_dir();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-VARIANT-MONOSTATE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "choice".to_owned(),
                cpp_type: "const std::variant<std::monostate, std::uint32_t> &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <variant>"));
        assert!(main.contains("std::variant<std::monostate, std::uint32_t> choice"));
        assert!(main.contains("std::monostate _bhf_variant_choice_0{}"));
        assert!(main.contains("std::in_place_index<0>"));
        assert!(main.contains("parse(choice);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-variant-monostate") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_enum_class_param() {
        let out = temp_dir("cpp-emit-enum-class");
        let runtime = runtime_dir();
        let header_text = r#"
            enum class Mode { Fast, Safe };
            int parse(Mode mode);
        "#;
        fs::write(out.join("mode.hpp"), header_text).unwrap();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-ENUM-CLASS".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("mode.hpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "Mode".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["mode.hpp".to_owned()],
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![cpp_parser::parse_cpp_type_defs(header_text).unwrap()],
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("Mode mode = (Mode)Mode::Fast"));
        assert!(main.contains("case 1: mode = (Mode)Mode::Safe; break"));
        assert!(main.contains("parse(mode);"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-enum-class") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_source_only_namespaced_enum_class_param() {
        let out = temp_dir("cpp-emit-namespaced-enum-class");
        let runtime = runtime_dir();
        let source_text = r#"
            namespace gov {
            enum class Mode { Fast, Safe };
            int parse(Mode mode) { return mode == Mode::Fast ? 1 : 0; }
            }
        "#;
        fs::write(out.join("parser.cpp"), source_text).unwrap();
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["gov".to_owned()];
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-NS-ENUM-CLASS".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("parser.cpp"),
            target,
            params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "Mode".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![cpp_parser::parse_cpp_type_defs(source_text).unwrap()],
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include \"parser.cpp\""));
        assert!(main.contains("using namespace gov;"));
        assert!(main.contains("Mode mode = (Mode)gov::Mode::Fast"));
        assert!(main.contains("gov::parse(mode);"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-ns-enum-class") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_decodes_qualified_namespaced_enum_class_param() {
        let out = temp_dir("cpp-emit-qualified-enum-class");
        let runtime = runtime_dir();
        let source_text = r#"
            namespace gov {
            enum class Mode { Fast, Safe };
            }
            int parse(gov::Mode mode) { return mode == gov::Mode::Fast ? 1 : 0; }
        "#;
        fs::write(out.join("parser.cpp"), source_text).unwrap();
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-QUAL-ENUM-CLASS".to_owned(),
            output_dir: out.clone(),
            source_path: out.join("parser.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "mode".to_owned(),
                cpp_type: "gov::Mode".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: vec![out.clone()],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: runtime.clone(),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: vec![cpp_parser::parse_cpp_type_defs(source_text).unwrap()],
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("#include \"parser.cpp\""));
        assert!(main.contains("gov::Mode mode = (gov::Mode)gov::Mode::Fast"));
        assert!(main.contains("case 1: mode = (gov::Mode)gov::Mode::Safe; break"));
        assert!(main.contains("parse(mode);"));

        if let Some(extra_flags) = clangxx_compile_flags("cpp-qualified-enum-class") {
            let obj = out.join("main.o");
            let output = Command::new("clang++")
                .args(extra_flags)
                .arg("-I")
                .arg(&runtime)
                .args(["-std=c++17", "-c"])
                .arg(&result.main_cpp)
                .arg("-o")
                .arg(&obj)
                .output()
                .expect("run clang++");
            assert!(
                output.status.success(),
                "clang++ failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn generate_cpp_direct_harness_includes_filesystem_for_path() {
        let out = temp_dir("cpp-emit-filesystem-path");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP007".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("load"),
            params: vec![CppParameter {
                name: "path".to_owned(),
                cpp_type: "const std::filesystem::path &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <filesystem>"));
        assert!(main.contains("std::filesystem::path path(_tmp_path)"));
        assert!(main.contains("load(path);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));
    }

    #[test]
    fn generate_cpp_direct_harness_includes_chrono_for_duration() {
        let out = temp_dir("cpp-emit-chrono-duration");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP-CHRONO".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/x.cpp"),
            target: cppfunction("parse"),
            params: vec![CppParameter {
                name: "timeout".to_owned(),
                cpp_type: "const std::chrono::milliseconds &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();
        assert!(main.contains("#include <chrono>"));
        assert!(main.contains("std::chrono::milliseconds timeout(bhf_bounded_i32"));
        assert!(main.contains("parse(timeout);"));
        assert!(makefile.contains("CXX_STD ?= gnu++20"));

        let Some(cxx_flags) = clangxx_compile_flags("cppgen-chrono-duration") else {
            eprintln!(
                "skipping generated C++ chrono harness compile: clang++ C++ headers unavailable"
            );
            return;
        };
        let obj = result.main_cpp.with_extension("o");
        let output = Command::new("clang++")
            .args(&cxx_flags)
            .arg("-std=c++17")
            .arg("-I")
            .arg(runtime_dir())
            .arg("-c")
            .arg(&result.main_cpp)
            .arg("-o")
            .arg(&obj)
            .output()
            .expect("spawn clang++");
        assert!(
            output.status.success(),
            "clang++ failed\nstdout:\n{}\nstderr:\n{}\nmain.cpp:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
            main
        );
    }

    #[test]
    fn existing_libfuzzer_entrypoint_is_not_wrapped_recursively() {
        let out = temp_dir("cpp-existing-libfuzzer");
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-CPP003".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/fuzz.cc"),
            target: cppfunction("LLVMFuzzerTestOneInput"),
            params: vec![
                CppParameter {
                    name: "data".to_owned(),
                    cpp_type: "const uint8_t *".to_owned(),
                },
                CppParameter {
                    name: "size".to_owned(),
                    cpp_type: "size_t".to_owned(),
                },
            ],
            return_type: "int".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/fuzz.cc")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        let makefile = fs::read_to_string(&result.makefile).unwrap();

        // #408: a passthrough C++ target must now get the bhf driver (the
        // edge-coverage runtime + persistent framed fork-server main), NOT the
        // old no-op that left libFuzzer's own main to mis-drive the binary —
        // which produced zero coverage and empty-testcase false positives.
        assert!(
            main.contains("__sanitizer_cov_trace_pc_guard") && main.contains("BHF_FRAMED"),
            "passthrough C++ must emit the bhf coverage/framed driver: {main}"
        );
        // The project supplies the entrypoint body; the driver only DECLARES it
        // (forward declaration, ends with ';') and calls it once through the
        // wrapper. It must NEVER be redefined here (ODR clash with the project's
        // definition) nor call itself (infinite recursion).
        assert!(
            main.contains(
                "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);"
            ),
            "passthrough must forward-declare the project entrypoint: {main}"
        );
        assert!(
            !main.contains("LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {"),
            "existing libFuzzer target must not be redefined: {main}"
        );
        assert!(
            main.contains("bhf_run_one_bytes")
                && main.contains("LLVMFuzzerTestOneInput(data, size)"),
            "driver should call the project entrypoint through the wrapper: {main}"
        );
        // Makefile: coverage on, libFuzzer's main off (so the bhf main is
        // the only entrypoint).
        assert!(
            makefile.contains("-fsanitize-coverage=trace-pc-guard,trace-cmp"),
            "passthrough makefile must instrument coverage: {makefile}"
        );
        // The default build drops libFuzzer's main; libFuzzer is a separate opt-in
        // target for external drivers, so `-fsanitize=fuzzer` is only in it.
        let cxxflags_line = makefile
            .lines()
            .find(|l| l.trim_start().starts_with("CXXFLAGS ?="))
            .unwrap_or("");
        assert!(
            !cxxflags_line.contains("fuzzer"),
            "passthrough makefile default recipe must drop libFuzzer's main: {makefile}"
        );
        assert!(
            makefile.contains("libfuzzer: main_libfuzzer")
                && makefile.contains("-fsanitize=fuzzer,address,undefined"),
            "a dedicated opt-in libFuzzer target must exist: {makefile}"
        );
        assert!(
            makefile.contains("-fsanitize=address,undefined -fno-sanitize=function,vptr,alignment"),
            "passthrough makefile must subtract FP-prone UBSan checks: {makefile}"
        );
        assert!(
            makefile.contains("main.cpp /tmp/fuzz.cc"),
            "project fuzz source should still be linked: {makefile}"
        );
    }

    // ── Factory-receiver emission tests ────────────────────────────────────

    /// A factory plan with an instance-method factory returning a pointer must
    /// emit: owner default-construction, `auto _bhf_receiver = _bhf_owner.Factory(args)`,
    /// a null guard `if (_bhf_receiver) { _bhf_receiver->method(...); }`, and the
    /// owner declaration must precede the receiver so it outlives the call.
    #[test]
    fn generate_cpp_factory_pointer_receiver_emits_owner_and_null_guard() {
        let out = temp_dir("cpp-factory-pointer");
        let mut target = cppfunction("IntAttribute");
        target.qualifier_path = vec!["tinyxml2".to_owned(), "XMLElement".to_owned()];
        target.api.class_name = Some("XMLElement".to_owned());
        target.api.namespace_path = vec!["tinyxml2".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-FACTORY-PTR".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/tinyxml2.cpp"),
            target,
            params: vec![CppParameter {
                name: "name".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["tinyxml2.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: Some(CppFactoryPlan {
                owner_type: Some("tinyxml2::XMLDocument".to_owned()),
                owner_method_is_static: false,
                factory_method: "NewElement".to_owned(),
                factory_params: vec![CppParameter {
                    name: "name".to_owned(),
                    cpp_type: "const char *".to_owned(),
                }],
                receiver_is_pointer: true,
            }),
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        // Owner must be declared and kept in scope.
        assert!(
            main.contains("tinyxml2::XMLDocument _bhf_owner;"),
            "owner must be stack-allocated: {main}"
        );
        // Receiver must be obtained from the factory call (using auto).
        assert!(
            main.contains("auto _bhf_receiver = _bhf_owner.NewElement("),
            "factory call must use _bhf_owner: {main}"
        );
        // Null guard: pointer receivers may be null.
        assert!(
            main.contains("if (_bhf_receiver)"),
            "pointer factory receiver must be null-guarded: {main}"
        );
        // Method call must use -> access.
        assert!(
            main.contains("_bhf_receiver->IntAttribute("),
            "method on pointer receiver must use -> access: {main}"
        );
        // R must be declared before the if-guard so (void)R compiles outside it.
        let r_decl_pos = main.find("int R{}").or_else(|| main.find("int R ="));
        let if_guard_pos = main.find("if (_bhf_receiver)");
        assert!(
            r_decl_pos.is_some() && if_guard_pos.is_some() && r_decl_pos < if_guard_pos,
            "R must be declared before the null guard: {main}"
        );
        // Owner declaration must precede the receiver (LIFETIME: owner must outlive call).
        let owner_pos = main.find("tinyxml2::XMLDocument _bhf_owner;");
        let receiver_pos = main.find("auto _bhf_receiver = _bhf_owner.NewElement(");
        assert!(
            owner_pos.is_some() && receiver_pos.is_some() && owner_pos < receiver_pos,
            "owner must be declared before receiver: {main}"
        );
        // Normal receiver construction path must NOT be emitted.
        assert!(
            !main.contains("tinyxml2::XMLElement _bhf_receiver"),
            "factory path must not also emit direct receiver construction: {main}"
        );
    }

    /// A factory plan with a VALUE (non-pointer) return must use `.` access and
    /// must NOT emit a null guard.
    #[test]
    fn generate_cpp_factory_value_receiver_uses_dot_access_without_null_guard() {
        let out = temp_dir("cpp-factory-value");
        let mut target = cppfunction("parse");
        target.qualifier_path = vec!["acme".to_owned(), "Token".to_owned()];
        target.api.class_name = Some("Token".to_owned());
        target.api.namespace_path = vec!["acme".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-FACTORY-VAL".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/acme.cpp"),
            target,
            params: vec![CppParameter {
                name: "input".to_owned(),
                cpp_type: "const std::string &".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["acme.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: Some(CppFactoryPlan {
                owner_type: Some("acme::Lexer".to_owned()),
                owner_method_is_static: false,
                factory_method: "MakeToken".to_owned(),
                factory_params: Vec::new(),
                receiver_is_pointer: false,
            }),
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        assert!(
            main.contains("acme::Lexer _bhf_owner;"),
            "owner must be emitted: {main}"
        );
        assert!(
            main.contains("auto _bhf_receiver = _bhf_owner.MakeToken()"),
            "value factory call must be emitted: {main}"
        );
        // Value receiver uses `.` not `->`.
        assert!(
            main.contains("_bhf_receiver.parse("),
            "value receiver must use . access: {main}"
        );
        // No null guard for a value return.
        assert!(
            !main.contains("if (_bhf_receiver)"),
            "value factory receiver must NOT be null-guarded: {main}"
        );
    }

    /// A factory plan with NO owner (free-function factory) must omit the owner
    /// declaration and call the factory function directly.
    #[test]
    fn generate_cpp_free_function_factory_receiver_omits_owner() {
        let out = temp_dir("cpp-factory-free-fn");
        let mut target = cppfunction("encode");
        target.qualifier_path = vec!["codec".to_owned(), "Frame".to_owned()];
        target.api.class_name = Some("Frame".to_owned());
        target.api.namespace_path = vec!["codec".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-FACTORY-FREE".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/codec.cpp"),
            target,
            params: vec![CppParameter {
                name: "buf".to_owned(),
                cpp_type: "const uint8_t *".to_owned(),
            }],
            return_type: "int".to_owned(),
            target_includes: vec!["codec.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: Some(CppFactoryPlan {
                owner_type: None, // free-function factory
                owner_method_is_static: false,
                factory_method: "codec::create_frame".to_owned(),
                factory_params: Vec::new(),
                receiver_is_pointer: true,
            }),
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        // No owner declaration.
        assert!(
            !main.contains("_bhf_owner"),
            "free-function factory must not emit an owner: {main}"
        );
        // Direct free-function call.
        assert!(
            main.contains("auto _bhf_receiver = codec::create_frame()"),
            "free-function factory call must be emitted: {main}"
        );
        assert!(
            main.contains("if (_bhf_receiver)"),
            "pointer result from free-function factory must be null-guarded: {main}"
        );
        assert!(
            main.contains("_bhf_receiver->encode("),
            "method on pointer receiver must use -> access: {main}"
        );
    }

    /// When `factory_plan` is `None` and the class has a normal public default
    /// constructor, the harness must use direct construction — the factory path
    /// must not activate.
    #[test]
    fn generate_cpp_no_factory_plan_uses_direct_receiver_construction() {
        let out = temp_dir("cpp-factory-absent");
        let mut target = cppfunction("value");
        target.qualifier_path = vec!["acme".to_owned(), "Item".to_owned()];
        target.api.class_name = Some("Item".to_owned());
        target.api.namespace_path = vec!["acme".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppDirectArgs {
            decoder_limits: Default::default(),
            force: false,
            harness_id: "H-NOFACTORY".to_owned(),
            output_dir: out.clone(),
            source_path: PathBuf::from("/tmp/acme.cpp"),
            target,
            params: Vec::new(),
            return_type: "int".to_owned(),
            target_includes: vec!["acme.h".to_owned()],
            target_includes_dirs: vec![PathBuf::from("/tmp")],
            target_sources: Vec::new(),
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_direct_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        // No factory emission when factory_plan is None.
        assert!(
            !main.contains("_bhf_owner"),
            "no factory_plan must not emit an owner: {main}"
        );
        assert!(
            !main.contains("auto _bhf_receiver"),
            "no factory_plan must not emit auto factory receiver: {main}"
        );
        // Normal receiver path (declaring class name) must be used.
        assert!(
            main.contains("acme::Item _bhf_receiver"),
            "direct receiver construction must be used: {main}"
        );
        assert!(
            main.contains("_bhf_receiver.value("),
            "normal . access must be used: {main}"
        );
    }

    #[test]
    fn callable_member_name_accepts_identifiers_and_operators_only() {
        assert!(cpp_callable_member_name("open"));
        assert!(cpp_callable_member_name("_private0"));
        assert!(cpp_callable_member_name("operator=="));
        assert!(cpp_callable_member_name("operator()"));
        // Parse-recovery artifacts the emitter must never call as `receiver.X(...)`.
        assert!(!cpp_callable_member_name("~MappedFile"));
        assert!(!cpp_callable_member_name("A::b"));
        assert!(!cpp_callable_member_name("bad<int>"));
        assert!(!cpp_callable_member_name("operator"));
        assert!(!cpp_callable_member_name(""));
        assert!(!cpp_callable_member_name("9start"));
    }

    #[test]
    fn return_type_emittable_rejects_bare_keyword_artifacts() {
        assert!(cpp_return_type_emittable("int"));
        assert!(cpp_return_type_emittable("std::string"));
        assert!(cpp_return_type_emittable("const char *"));
        // A legal elaborated-type-specifier is two tokens and stays allowed.
        assert!(cpp_return_type_emittable("struct Foo"));
        // `namespace detail_fp {` mis-recovered as a function surfaces here.
        assert!(!cpp_return_type_emittable("namespace"));
        assert!(!cpp_return_type_emittable("template"));
        assert!(!cpp_return_type_emittable("using"));
    }

    #[test]
    fn pugixml_owned_buffer_is_not_freed_by_sequence_harness() {
        let out = temp_dir("cpp-pugixml-owned-buffer");
        let mut target = cppfunction("load_buffer_inplace_own");
        target.qualifier_path = vec!["pugi".to_owned(), "xml_document".to_owned()];
        target.api.class_name = Some("xml_document".to_owned());
        target.api.namespace_path = vec!["pugi".to_owned()];
        target.api.is_method = true;
        let buffer = CppParameter {
            name: "contents".to_owned(),
            cpp_type: "void *".to_owned(),
        };
        let size = CppParameter {
            name: "size".to_owned(),
            cpp_type: "size_t".to_owned(),
        };
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-PUGI-OWN".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/pugixml.cpp"),
            target,
            params: vec![buffer.clone(), size.clone()],
            return_type: "xml_parse_result".to_owned(),
            target_includes: vec!["pugixml.hpp".to_owned()],
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/pugixml.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            lifecycle_steps: vec![
                CppLifecycleStep {
                    name: "load_buffer_inplace_own".to_owned(),
                    params: vec![buffer.clone(), size.clone()],
                    return_type: "xml_parse_result".to_owned(),
                },
                CppLifecycleStep {
                    name: "load_buffer_inplace".to_owned(),
                    params: vec![buffer.clone(), size.clone()],
                    return_type: "xml_parse_result".to_owned(),
                },
            ],
            protocol_steps: vec![CppProtocolStep {
                step: CppLifecycleStep {
                    name: "load_buffer_inplace_own".to_owned(),
                    params: vec![buffer, size],
                    return_type: "xml_parse_result".to_owned(),
                },
                args: vec![CppProtocolArg::Decode, CppProtocolArg::Decode],
                marks_target: true,
            }],
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };
        let result = generate_cpp_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();
        assert!(main.contains("_bhf_receiver.load_buffer_inplace_own("));
        assert!(!main.contains("free(_bhf_step0_contents)"), "{main}");
        assert!(!main.contains("free(_bhf_protocol0_contents)"), "{main}");
        assert!(!main.contains("free(contents)"), "{main}");
        assert!(!main.contains("free(_bhf_step1_contents)"), "{main}");
        assert!(
            main.contains("_bhf_retained_buffers.push_back(_bhf_step1_contents)"),
            "{main}"
        );
        assert!(main.contains("_bhf_receiver.reset();"), "{main}");
        assert!(
            main.contains("for (void *_bhf_retained : _bhf_retained_buffers) free(_bhf_retained)"),
            "{main}"
        );
    }

    /// ROBUSTNESS (campaign: tinyobjloader): a lifecycle harness must DROP a step
    /// the parser mis-attributed as a member whose call would not compile — a
    /// non-identifier name or a `namespace`-typed parse artifact — while still
    /// emitting the genuine member, rather than producing an un-compilable harness.
    #[test]
    fn sequence_harness_drops_uncompilable_lifecycle_steps() {
        let out = temp_dir("cpp-sequence-drop-artifacts");
        let mut target = cppfunction("open");
        target.qualifier_path = vec!["ns".to_owned(), "MappedFile".to_owned()];
        target.api.class_name = Some("MappedFile".to_owned());
        target.api.namespace_path = vec!["ns".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CPP-DROP".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/mapped.cpp"),
            target,
            params: vec![CppParameter {
                name: "path".to_owned(),
                cpp_type: "const char *".to_owned(),
            }],
            return_type: "bool".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/mapped.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            lifecycle_steps: vec![
                // genuine member: must be emitted
                CppLifecycleStep {
                    name: "close".to_owned(),
                    params: Vec::new(),
                    return_type: "void".to_owned(),
                },
                // `namespace detail_fp {` mis-parsed as a method: must be dropped
                CppLifecycleStep {
                    name: "detail_fp".to_owned(),
                    params: Vec::new(),
                    return_type: "namespace".to_owned(),
                },
                // non-identifier name: must be dropped
                CppLifecycleStep {
                    name: "bad<int>".to_owned(),
                    params: Vec::new(),
                    return_type: "int".to_owned(),
                },
            ],
            protocol_steps: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let result = generate_cpp_sequence_harness(args).unwrap();
        let main = fs::read_to_string(&result.main_cpp).unwrap();

        assert!(
            main.contains("_bhf_receiver.close("),
            "genuine member step must be emitted: {main}"
        );
        assert!(
            !main.contains("detail_fp"),
            "namespace artifact step must be dropped: {main}"
        );
        assert!(
            !main.contains("bad<int>"),
            "non-identifier step must be dropped: {main}"
        );
        assert!(
            !main.contains("namespace _bhf_step"),
            "no step may emit a `namespace`-typed result: {main}"
        );
    }

    /// ROBUSTNESS: a TARGET the parser handed us with a parse-artifact return type
    /// must SKIP cleanly (an `Err` the CLI surfaces as a skip reason) instead of
    /// emitting `namespace R = receiver.detail_fp();`.
    #[test]
    fn sequence_harness_skips_malformed_target_cleanly() {
        let out = temp_dir("cpp-sequence-bad-target");
        let mut target = cppfunction("detail_fp");
        target.qualifier_path = vec!["ns".to_owned(), "MappedFile".to_owned()];
        target.api.class_name = Some("MappedFile".to_owned());
        target.api.namespace_path = vec!["ns".to_owned()];
        target.api.is_method = true;
        let args = GenerateCppSequenceArgs {
            decoder_limits: Default::default(),
            harness_id: "H-CPP-BADTGT".to_owned(),
            output_dir: out,
            source_path: PathBuf::from("/tmp/mapped.cpp"),
            target,
            params: Vec::new(),
            return_type: "namespace".to_owned(),
            target_includes: Vec::new(),
            target_includes_dirs: Vec::new(),
            target_sources: vec![PathBuf::from("/tmp/mapped.cpp")],
            compile_flags: Vec::new(),
            c_runtime_include: PathBuf::from("/tmp/c_runtime"),
            using_namespaces: Vec::new(),
            result_cleanup: None,
            constructor_params: Vec::new(),
            lifecycle_steps: Vec::new(),
            protocol_steps: Vec::new(),
            type_defs: Vec::new(),
            default_constructible_classes: Vec::new(),
            parameter_constructions: Vec::new(),
            receiver_class_override: None,
            factory_plan: None,
        };

        let err = generate_cpp_sequence_harness(args).unwrap_err();
        assert!(
            matches!(err, HarnessGenError::UnsupportedParamType(_)),
            "malformed target must skip cleanly, got: {err:?}"
        );
    }
}
