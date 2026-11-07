# Provenance

This file links every non-trivial behaviour of `igs-iso9506-mms` to its source: a clause of a standard, an
observation test, or third-party code under a permissive licence. The project is a clean-room
implementation: no protocol behaviour without a source recorded here or in a
`// ISO 9506-2 §8.2` comment.

The ISO and IEC standards are licensed and are not distributed with this repository. The references
below point to clauses; they do not reproduce the text of the standards.

## Reference standards

| Standard | Edition | Use |
| --- | --- | --- |
| ISO 9506-1 | 2003 | MMS services |
| ISO 9506-2 | 2003 | MMS protocol, ASN.1 |
| ITU-T X.224, X.225, X.226, X.227 | Editions in force | Transport, session, presentation, ACSE (free texts) |
| ITU-T X.690 | 02/2021 | BER (free text) |
| ITU-T X.501, X.520 | 11/1993 | `Name`, for the AP-title form 1 (free texts) |
| RFC 1006, RFC 2126 | | TPKT over TCP |
| IEC 62351-3 | 2023 | TLS profile |
| IEC 60870-6-702 | 2014 | Stack and services required by TASE.2 |

## Decisions on ambiguities in the standard

Confidence: **high** when the sources agree; **medium** when they contradict each other or are
silent, to be confirmed by an observation test against other implementations.

### D-001 — Generated types come from the variant with all conditions true

- **Decision**: the module of ISO 9506-2 is written with `IF`, `ELSE` and `ENDIF` directives
  (§5.14). The generated types use the `IF` branches. What a given association may use is checked
  separately, against the CBBs negotiated by Initiate.
- **Sources**: ISO 9506-2 §5.14, §5.15.
- **Confidence**: high.
- **Test**: to be written (task C7).

### D-002 — Defects of the published module

- **Decision**: the published module has unbalanced directives and misplaced punctuation, settled
  by 23 decisions in the private standards repository (pages 33, 35, 45, 52, 53, 60, 61, 94, 97,
  113, 119, 166). Lines of prose set in the code font (pages 60, 94) are not part of the module.
  `filename` on page 61 is read as the type `FileName`.
- **Sources**: ISO 9506-2, PDF, each page checked; parallel constructions of the same module.
- **Confidence**: high, except the place of the `ENDIF` of page 119: medium.
- **Test**: `cargo xtask codegen` parses every type of the corrected modules and fails otherwise;
  `crates/igs-iso9506-mms-codec/tests/generated.rs` checks the counts.

### D-003 — The project writes its own BER codec and generator

- **Decision**: the codec and `xtask codegen` are written in this project; `rasn` and
  `rasn-compiler` are not used. Task F3 compared the two on the criteria of the plan, in order.
- **Criterion 1, rule 8 guarantees**: does not separate them. `rasn` 0.30 returned an error on
  nesting up to 100,000 levels and on oversized lengths, on a 2 MiB stack, and did not panic on
  3 million noisy inputs. Its depth limit is fixed at 128, its decoding path is outside our lints,
  and it holds two `unsafe` blocks. The prototype of this project gave the same results with the
  lints of rule 8 active.
- **Criterion 2, extension markers**: `rasn-compiler` 0.16 refuses the end marker, in the two
  service CHOICEs and in five ACSE APDUs. The prototype reads them.
- **Criterion 3, no hand edits**: separates them. After three rewrites of the input (end markers,
  ACSE constraints, classes and information objects removed), `rasn-compiler` still produced code
  with 63 compile errors, 15 of them in the main MMS module. The prototype's output compiled
  unedited.
- **Criterion 4, dependency**: not justified, 35 crates for a function that the project can hold.
- **Also**: `rasn` rejects an unknown tag, whereas the scope asks for an unsupported variant that
  keeps the raw bytes. A hand-written wrapper would be needed.
- **Limits of the trial**: the prototype covers three productions and leaves service and ACSE
  field contents raw. The noise run is not a fuzzing campaign. `rasn-compiler` was tried at one
  version, with quick rewrites of the input.
- **Sources**: `docs/ai-log/F3.md`.
- **Confidence**: high for criteria 2 and 3.
- **Test**: the fuzz and property tests of the codec tasks.

### D-004 — Scope of the generated types

- **Decision**: the generator emits the types reachable from the MMS PDU and the ACSE APDU. The
  service CHOICEs keep the services that the profile requires and gain an `Unsupported` variant.
  Modifiers, the `service-ext` details, additional services, service-specific error information
  and `Name` stay raw BER. Every service, CBB and code stays in the tables, in or out of scope.
- **Sources**: IEC 60870-6-702 annex A, tables A.17 to A.32; the scope of `IMPLEMENTATION.md`.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/generated.rs`.

### D-005 — Integers and DEFAULT in the generated types, for now

- **Decision**: an INTEGER is an `i64` in a newtype that carries its named values and allowed
  ranges; a component with DEFAULT is an `Option`, and its value stays in the component table.
  Range-checked constructors and the default values on decoding come with tasks C5 to C7.
- **Sources**: rule of strong types in `IMPLEMENTATION.md` section 2; X.680.
- **Confidence**: medium: `Data` may carry an integer wider than 64 bits, settled by D-012.
- **Test**: `crates/igs-iso9506-mms-codec/tests/common_types.rs` (task C6).

### D-006 — Dependencies of `xtask`

- **Decision**: `xtask` reads YAML with `serde` and `serde-saphyr` (MIT or Apache-2.0). It requires
  Rust 1.89, while the library crates stay at 1.85; it is not published and runs on a development
  machine only, so the minimum-version job excludes it. `serde_yaml` would need an advisory
  exception. `Unicode-3.0` joins the accepted licences for `unicode-ident`, a permissive licence
  on data tables, reached through `serde_derive`; `igs-iec104` accepts it too.
- **Sources**: rule 9 of `IMPLEMENTATION.md`; `cargo deny check`.
- **Confidence**: high.
- **Test**: the workflow and `cargo deny check`.

### D-007 — What the BER layer accepts and writes

- **Decision**: decoding accepts every choice X.690 leaves to a BER sender: long or short length
  forms, extra length octets (§8.1.3.5, note 2), the indefinite form on constructed encodings,
  constructed BIT STRING, OCTET STRING and character strings, any non-zero octet as TRUE. It
  refuses what X.690 forbids to every sender: an INTEGER with a redundant leading octet (§8.3.2),
  a tag number in a needless high-tag form (§8.1.2.4), the reserved length octet. Encoding writes
  definite lengths in the fewest octets, primitive strings and TRUE as `FF`, as DER does.
  GraphicString is read without escape sequences, so as printable ASCII. Nesting stops at 64
  constructed levels by default, a value the caller can change.
- **Sources**: ITU-T X.690 §8.1 to §8.8, §8.19, §8.23, §10, §11.1.
- **Confidence**: medium for the refusal of redundant INTEGER octets and for GraphicString:
  some peers might send them. To check on the bench (tasks L6, T4, S4).
- **Test**: `crates/igs-iso9506-mms-codec/tests/ber.rs`.

### D-008 — The TPDU decoder checks structure, the connection checks class 0

- **Decision**: decoding accepts in a CR or CC TPDU what class 0 does not allow but a peer sends:
  TPDU sizes of 4096 and 8192 octets, other classes, user data (RFC 1006 allows it for testing),
  a CR TPDU over 128 octets. The connection of task L2 decides what to accept. Decoding refuses
  what breaks the structure: a reserved length indicator, a header that does not fit, a parameter
  running past the header, a TPDU type outside class 0, a DT TPDU with a variable part. Each
  refusal carries the ER reject cause and the offset of the octet in fault (X.224 §13.12). The
  reserved octet of the TPKT header is ignored on receipt and written as zero.
- **Sources**: ITU-T X.224 §13.2 to §13.5, §13.7, §13.12; RFC 1006 §6. Observation: the reference
  client of the bench proposes 8192 octets and the reference server confirms it (task F5).
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/transport.rs`.

### D-009 — Session SPDUs: what is decoded, and what is kept

- **Decision**: the SPDUs of the kernel and duplex functional units are decoded field by field:
  CONNECT, ACCEPT, REFUSE, FINISH, DISCONNECT, ABORT, ABORT ACCEPT, GIVE TOKENS and DATA TRANSFER.
  Other SPDUs and unknown parameter codes, which §8.2.6 declares valid, are kept as received.
  A TSDU holds one SPDU, or GIVE TOKENS or PLEASE TOKENS followed by one category 2 SPDU (basic
  concatenation); extended concatenation, segmenting, OVERFLOW ACCEPT and CONNECT DATA OVERFLOW are
  out of the profile. Units are written in increasing code order (§8.2.6) and read in any order.
  A three-octet length indicator is read for short lengths too, and written only from 255. User
  data of a CONNECT SPDU goes in the User Data parameter up to 512 octets, else in the Extended User
  Data parameter up to 10 240.
- **Sources**: ITU-T X.225 §6.3.7, §8.2, §8.3.1 to §8.3.11, §8.3.16; IEC 60870-6-702 table A.61
  (version 2, duplex, extended concatenation and overflow out of scope). Observation: the CONNECT,
  ACCEPT and GIVE TOKENS with DATA TRANSFER of the bench peers decode and re-encode octet for octet.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/session.rs`.

### D-010 — Presentation PPDUs, written by hand on the BER layer

- **Decision**: CP, CPC, CPA, CPR, ARU and ARP are coded by hand on the BER layer of task C1, not
  generated: one small module, needed before the generator has decoding (tasks C5 to C7). Normal
  mode is decoded; X.410-1984 mode, outside the profile, is kept as raw BER. As §8.5 requires, a
  CP PPDU ignores undefined elements and unnamed bits, while the other PPDUs refuse them, as they
  refuse numbers with no name. The components of a SET are read in any order and written in tag
  order. User data is decoded in both encodings: simple, which the profile requires (IEC
  60870-6-702 §6.4), and full, which the bench peers use. The contents of a single-ASN1-type PDV
  must be exactly one encoding; they are kept as octets for ACSE and MMS to decode.
- **Sources**: ITU-T X.226 §8.2 to §8.5; IEC 60870-6-702 §6.4, table A.60. Observation: the CP,
  CPA and data user data of the bench peers decode and re-encode octet for octet.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/presentation.rs`.

### D-011 — The generator writes the codec; the ACSE APDUs use it

- **Decision**: `xtask codegen` gives every generated type a decoder and an encoder, through the
  `Codec` trait of `crate::asn`, a small runtime written by hand. The ACSE APDUs are these
  generated types; `crate::acse` adds what the module does not say. The rules:
  - Tags are compared on class and number. An implicit tag replaces the identifier, an explicit
    one wraps the value; a CHOICE or an open type is always tagged explicitly (X.680 §31.2.7).
  - A SEQUENCE is read in order. An unknown element is refused, except in an incoming AARQ, which
    ignores it (X.227 §7.4); it is not written back. Bits without a name are kept.
  - At generation, the tags of the alternatives of a CHOICE, and those of an optional component
    and the components that may follow it, must differ (X.680 §25.6, §29.3).
  - A value or size constraint without an extension marker is checked on decoding and on
    encoding, and through a `new` constructor. An ENUMERATED without an extension marker admits
    only its named values (X.680 §20). The four CBB bit strings are not checked: this edition
    fixes their size, while the bench peer sends 85 and 11 bits. Task C7 settles this.
  - A component with DEFAULT stays an `Option`: absent means the default value, and a value
    received is written back. This replaces the default values on decoding announced in D-005.
  - `EXTERNAL`, `EMBEDDED PDV`, open types and the opaque types of D-004 are kept as one BER
    encoding with their own tag, its length rewritten in the definite form. The tags of `Name`
    and `RelativeDistinguishedName` come from X.501 §9.2 and §9.3. Raw octets are checked before
    they are written.
  - An AP title or AE qualifier is decoded in form 2 and kept raw in form 1, as the plan asks;
    X.227 §10.3.1 and IEC 60870-6-702 table A.58 require receiving both forms.
  - A protocol version field that is absent means version 1 (X.227 §7.1.3.2, note 3).
  - User information is read with `acse::External` (X.690 §8.18).
- **Sources**: ITU-T X.227 §7.1.3.2, §7.1.4.1, §7.4, §9, §10.3.1, amendment 1; X.680 §20,
  §25.6, §29.3, §31.2.7, §31.2.9; X.690 §8.14, §8.18; X.501 §9.2, §9.3; IEC 60870-6-702 tables
  A.47, A.52 to A.58. Observation: the AARQ and AARE of the bench peers decode and re-encode octet
  for octet.
- **Confidence**: high for the ACSE rules; medium for the strict checks of the MMS constraints,
  to be confirmed against peers in tasks C7, L6 and T4.
- **Test**: `crates/igs-iso9506-mms-codec/tests/acse.rs`, `tests/generated.rs`, and the unit tests
  of `xtask/src/emit.rs`.

### D-012 — Common MMS types: the profile's branch, wide integers, the prose checked

- **Decision**: the common types stay generated; `crate::mms` adds what their prose says.
  - **Strings**: the data files keep the IF branches of the directives. The TASE.2 profile has no
    `char` CBB, so the generator takes the ELSE branch of `Identifier`, `MMSString` and
    `MMS255String`: VisibleStrings, not UTF8Strings. An Identifier has 1 to 32 characters among
    letters, digits, `$` and `_`.
  - **Integers of `Data`**: `integer` is an `i128`; `unsigned` and `bcd`, which shall not be
    negative, are `u128`. A type description gives an integer at most 127 bits (`Unsigned8`), so
    every value of a described type fits; a wider one is refused. This settles D-005.
  - **TimeOfDay**: 4 or 6 octets, the four top bits zero; read as milliseconds since midnight and
    the day since 1 January 1984. Values up to the 28-bit maximum are accepted, as the clause
    sets no other bound.
  - **FloatingPoint**: at least two octets; the exponent width is above zero and leaves room for
    the sign. The IEEE 754 single and double forms are written as is. Any width is read by the
    general rule, and narrowed to `f32` or `f64` with the rounding rules of the clause: rounded up
    when the first bit that does not fit is one, so a tie goes away from zero, unlike IEEE 754;
    a magnitude too large becomes an infinity, one too small a zero. The subnormal range of the
    target counts as representable.
  - The placeholders of the ELSE branches (`array [1] IMPLICIT NULL` without `str1`, and the
    like) are not read: the profile requires `str1` and `str2`.
- **Sources**: ISO 9506-2 §7.5.1, §7.5.2, §7.5.3, §7.5.6, §14.2.1, §14.4.1 to §14.4.3; ISO
  9506-1 §14.2.1; IEC 60870-6-702 table A.19.
- **Confidence**: high for the formats; medium for the strict alphabet of Identifier, to check on
  the bench (tasks L6, T4).
- **Test**: `crates/igs-iso9506-mms-codec/tests/common_types.rs`.

### D-013 — MMS PDUs: decoding the union of the directives, checking the CBBs apart

- **Decision**: decoding reads the union of the IF branches of ISO 9506-2; `mms::validate_cbb`
  then checks a PDU against the negotiation of the user that serves its service.
  - **Directives**:
    - The ELSE branches that only reserve a tag with a NULL are not read.
    - The components that an excluded CBB (`csr`, `cspi`) makes required inside its directive
      are optional: the Initiate PDUs of the bench peer omit them.
    - The `char` strings follow D-012.
  - **Unknown elements**: the Initiate request and response, and their details, ignore them
    (ISO 9506-2 §8.2). The Initiate error does not, as its type is the shared ServiceError.
  - **CBB bit strings**: read at any size. A sender encodes all the bits and a receiver ignores
    the bits it does not know (ISO 9506-1 §8.2.1.1.6, §8.2.1.1.8), so a missing bit reads as not
    supported. Writing the bits of this edition is left to the association (task L4). This
    settles the CBB size question left open in D-011.
  - **Context tags beyond the last alternative**: `Data` and `TypeDescription` keep them as raw
    BER. The bench peer sends `[17]`, which ISO 9506 does not define.
  - **Identifier**: it stays at 32 characters. The bench peer, an IEC 61850 server, names its
    objects with up to 39 characters; the two getNameList responses that carry such names are
    refused. This gap is recorded for the IEC 61850 phase.
  - **The check**:
    - A service, modifier, Cancel or Conclude must be supported by the user that serves it
      (ISO 9506-1 §8.2.1.1.8, §8.2.1.2.8). The CBBs required around the service in the tables
      must be negotiated.
    - Each parameter must have its CBB, as ISO 9506-1 §8.1.3.15 and the directives assign them:
      - `str1` for arrays and indexes, `str2` for structures, components and named access;
      - `vnam` for names, `vadr` for addresses and packed types, `vsca` for scattered access;
      - `valt` for alternate access and component names, `vlis` for list names;
      - `aco`, `sem`, `cspi` for their fields, and `csr` or `cspi` for the service extensions.
    - Data and type descriptions stay within the negotiated nesting level (§8.1.3.16).
    - The Initiate, Reject and error PDUs are not checked.
- **Sources**: ISO 9506-2 §7, §8.2, §10, §14 with their directives; ISO 9506-1 §8.1.3.15,
  §8.1.3.16, §8.2.1.1.6, §8.2.1.1.8, §8.2.1.2.6, §8.2.1.2.8; IEC 60870-6-702 table A.19.
  Observation: of 112 distinct PDUs exchanged by the reference clients and server, 110 decode.
  They meet the observed negotiation, and re-encode octet for octet, except a TRUE that the peer
  writes as `01` (D-007).
- **Confidence**: high for the structure. Medium for two points: `valt` for the component names
  of a type description (§8.1.3.15.4 read as written), and the strict identifier length.
- **Test**: `crates/igs-iso9506-mms-codec/tests/mms_pdus.rs`;
  `bench/tests/test_c7_reference_services.py`.

### D-014 — Property tests: generated strategies, and the encoders made to refuse

- **Decision**:
  - **Dependency**: `proptest` (MIT or Apache-2.0) is a development dependency, and an optional
    dependency of the codec behind the `proptest` feature. The MSRV-aware resolver picks
    version 1.11, the last that builds with Rust 1.85; 1.12 needs 1.88.
  - **Strategies**: `cargo xtask codegen` writes one for each generated type, on the hand-written
    module `crate::strategy`. Recursion spends one level per cycle; at depth zero, a type keeps
    only its alternatives that do not recurse, and lists are empty.
  - **Properties**: 10 000 cases each, in `tests/properties.rs`.
    - A generated value always encodes and decodes back to itself.
    - For the hand-written layers (TPDU, SPDU, PPDU, EXTERNAL), every value that the encoder
      accepts decodes back to itself; most of the values generated must be accepted.
    - Random bytes and mutated encodings never make a decoder or the CBB check panic.
  - **What they found**: four encoders wrote values that their own decoder refuses, or reads
    back otherwise. Each now refuses them on encoding, by the rules of its decoder:
    - TPDU: credit, class, options over 4 bits, TPDU number over 7, and a code of `other`
      that is not defined or has its own field;
    - SPDU: an empty Reason Code, references, selectors and Reflect over their bounds;
    - PPDU: the numbers and bits that the CPA, CPR and ARP refuse (X.226 §8.5).
- **Limits**:
  - An SPDU unit of `other` whose code an SPDU decodes in a field of its own is still written;
    the SPDU strategies leave `other` empty.
  - The strategies cover the root values of extensible constraints only.
- **Sources**: ITU-T X.224 §13, X.225 §8, X.226 §8.5 for the bounds, as read by the decoders of
  tasks C2 to C4.
- **Confidence**: high.
- **Test**: `crates/igs-iso9506-mms-codec/tests/properties.rs`, and one regression test for each
  fix in `tests/transport.rs`, `tests/session.rs` and `tests/presentation.rs`.

### D-015 — Link parameters: defaults and bounds

- **Decision**: `LinkConfig` (crate `igs-iso9506-mms-link`, module `config`) holds the selectors,
  the AP-title, the TPDU size, the timeouts and the limits proposed in the association. `validate`
  refuses a value outside the bounds below; the first refused value is returned.
  - Bounds:
    - transport selector: at most 243 octets alone, and 241 for the two together, so that the
      connection request fits its length indicator of 254 octets (X.224 §13.2.1);
      a present selector is never empty;
    - session selector: at most 16 octets;
    - presentation selector: at most 16 octets;
    - AP-title: an object identifier of at least two arcs, the first at most 2, and the second
      below 40 when the first is below 2;
    - outstanding requests, each way: 1 to 32 767 (an INTEGER of 16 bits, positive);
    - nesting level: 2 to 127 (the TASE.2 minimum; an INTEGER of 8 bits, positive).
  - Defaults:
    - selectors and AP-title omitted;
    - TPDU size 8192 octets;
    - connect timeout 10 s, request timeout 30 s;
    - 8 outstanding requests each way;
    - nesting level 2.
- **Reasons**:
  - Selectors omitted: X.224 §13.3.4 a) makes the transport selector optional when the network
    address identifies the entity; RFC 1006 connects to TCP port 102, which RFC 2126 reserves for
    the same use, so the endpoint is known without a transport selector. The session and presentation selectors are not mandatory in their connection requests
    (X.225 table of CN parameters; X.226 §6.2.2.3, §6.2.2.5). To be checked against the reference
    peer in task L6; if it refuses an omitted selector, the default changes and this entry is
    updated.
  - TPDU size 8192: the size that the reference client of the bench proposes and the reference
    server confirms (task F5, observed). X.224 §13.3.4 b) marks 4096 and 8192 octets as not allowed
    in class 0. The transport of 9506-1 Annex F and of 6-702 is RFC 1006 or RFC 2126, which allow
    larger TPDUs (RFC 2126 gives 65 531 octets as the maximum and the default). The proposal follows
    the peer; the connection accepts up to 8192 and settles the size used (D-016).
  - Nesting level 2: the TASE.2 minimum (6-702, stack requirements). A larger proposal would claim
    a depth that the decoders do not yet check against the negotiated value; the level is revisited
    in task L4.
  - Outstanding requests, timeouts: no clause gives a value (9506-2 §8.2 gives the types and the
    names only). They are operational choices, to revisit in tasks L5 and L6.
- **Sources**: ITU-T X.224 §13.3.4 a) and b); X.225, table of CN parameters (selectors, 8.3.1.17);
  X.226 §6.2.2.3, §6.2.2.5, §8.2 (Presentation-selector, OCTET STRING without a bound); X.227
  (AP-title, form 2); X.690 §8.19.4 (first two arcs); ISO 9506-2 §8.2 (types of the proposed
  limits); 6-702 stack requirements; RFC 1006 and RFC 2126 (TCP port 102, default TPDU size),
  read on the web; the RFC texts are not stored here.
- **Confidence**: high for the bounds, which follow the clauses; medium for the omitted selectors
  and the TPDU size (the bench confirms them in L6); low for the outstanding limit and the
  timeouts, which are operational.
- **Test**: `crates/igs-iso9506-mms-link/tests/config.rs` (14 tests: defaults, each bound at its
  edge, and each refused value).

### D-016 — Class 0 transport connection

- **Decision**: `Connection` (crate `igs-iso9506-mms-link`, module `transport`) is a sans-I/O state
  machine for one role. `handle(event, now)` takes an event (connect, octets received, TSDU to
  send, release, tick) and returns actions (octets to write, a TSDU to deliver, opened, closed,
  misuse). Time is a duration from any origin the caller chooses.
  - Establishment:
    - the CR has class 0, options 0, credit 0, no user data, reference 1 as source, zero as
      destination, the configured selectors, and the proposed TPDU size;
    - the responder declines a CR with a DR whose source reference is zero (X.224 §13.3.4 and the
      rule on unassigned references), with reason NOT_SPECIFIED when the class, options, credit or
      user data is not class 0's, and ADDRESS_UNKNOWN when the configured called selector differs;
    - the agreed size is the smaller of the proposed size and the responder's maximum; an absent
      size is the default of 128 octets (X.224 §13.3.4 b);
    - the initiator accepts a CC with its own reference as destination, class 0, options 0, credit
      0, no user data, and a size not above the proposed one; an absent size means 128;
    - the connect timeout runs from the CR; its expiry closes the connection.
  - Data transfer:
    - a DT TPDU has the length indicator, the code and the EOT octet, so it carries the agreed size
      minus three octets (X.224 §13.7.1); the number is zero, as class 0 has no sequence;
    - a TSDU is segmented into DT TPDUs with EOT on the last, and all but the last carry data
      (X.224 §6.3.3); an empty TSDU is one DT with EOT and no data;
    - reassembly is bounded: `MAX_TSDU` is 1 048 576 octets. A DT with more than the agreed size,
      an empty DT without EOT, or a TSDU above the bound closes the connection with a protocol error.
  - Release: class 0 releases implicitly, with the network connection (X.224 §5.4.4). A local
    release sends nothing; a DR from the peer while open closes without a reply.
  - Errors: a TPDU that does not decode, or whose type the state does not allow, gets an ER TPDU.
    Its cause is the reject cause of X.224 §13.12.3. It quotes the TPDU up to the octet in fault,
    which is the code for an unexpected type, and at most 248 octets otherwise. A broken TPKT
    framing closes without a reply, since no TPDU can be sent on it.
  - A call in the wrong state (connect, send) returns `Misuse` and changes nothing.
- **Sources**: ITU-T X.224 §5.4.4, §6.3.3, §8.2.3, §13.2.1, §13.3, §13.3.4, §13.7.1, §13.12; RFC 1006
  and RFC 2126 for the TCP environment, as read on the web.
- **Confidence**: high for segmentation, the bounds and the release; medium for the reading of an
  absent size in a CC as 128 (RFC 2126 gives 65 531 as the default; to be checked against the peer in
  L6), and for the value of the reference, which only has to be non-zero.
- **Test**: `crates/igs-iso9506-mms-link/tests/transport.rs`, 23 tests on a fake clock, with both
  roles and the octets passed by the test: establishment, negotiation, refusal, segmentation,
  reassembly with its bound, release, and each protocol error.

### D-017 — Session and presentation connection, without user data

- **Decision**: `upper::Connection` (crate `igs-iso9506-mms-link`, module `upper`) is a sans-I/O
  state machine over the transport connection of D-016. Its TSDUs carry the SPDUs, and its user
  data is empty in this task: the ACSE APDUs come with task L4.
  - Connect: the CONNECT SPDU carries the CP PPDU in normal mode, with the calling and called
    selectors of the configuration (session and presentation), the duplex functional unit, and
    protocol version 2. The CP proposes two presentation contexts, both in the basic encoding:
    ACSE (identifier 1) and MMS (identifier 3).
  - Presentation context identifiers are odd (X.226 §6.2.2.7). The values 1 and 3 are an arbitrary
    choice of this implementation, not taken from a clause.
  - Responder, judged on receipt of the CONNECT:
    - a called session selector that is not configured is refused by a REFUSE with reason 129,
      session selector unknown (X.225 §8.3.5.10); no CPR;
    - a called presentation selector that is not configured is refused by a REFUSE with reason 2,
      carrying a CPR with provider reason 3, called presentation address unknown (X.226 §6.2.4.9);
    - a CP that is not in normal mode is refused the same way, with provider reason 0;
    - otherwise the responder indicates the connection and waits for the user.
  - Accept: each proposed context is accepted when its abstract syntax is ACSE or MMS, and its
    transfer syntaxes include the basic encoding. Otherwise it is a provider rejection: reason 1
    (abstract syntax not supported) or 2 (proposed transfer syntaxes not supported) (X.226 §6.2.3
    result list, and the reasons of its §6.2.4.9 list).
  - Refuse by the user: a REFUSE with reason 2 carries a CPR with user rejection (result 1) for each
    context and no provider reason (X.226 §6.2.5.6, §6.2.5.7).
  - Release: FINISH with the transport kept (transport disconnect 0), answered at once by a
    DISCONNECT from the other end, which is then released (X.225 §8.3.6, §8.3.7). This layer has no
    user to wait for, so the answer is immediate.
  - Abort: the user abort is an ABORT with the user bit and the transport-released bit, with
    no user data (task L6: an empty ARU PPDU was dropped, see below). A protocol error is an ABORT with the protocol-error bit and the transport-released
    bit, without user data. An ABORT received counts as a user abort when its user bit is set.
  - Data transfer, added by task L4: a TSDU of GIVE TOKENS then DATA TRANSFER carries the user data
    (X.225 §6.3.7). A DATA TRANSFER alone is a protocol error; the encoder refuses to write one.
  - The CPA must accept the ACSE and MMS contexts, the first two proposed. Otherwise the initiator
    aborts with a protocol error (added in task L4, which needs both).
- **Sources**: ITU-T X.225 §6.3.7, §8.3.1, §8.3.4, §8.3.5.10, §8.3.6, §8.3.7, §8.3.9; X.226 §6.2.2.7,
  §6.2.3, §6.2.4.9, §6.2.5.5 to §6.2.5.8; ISO 9506-2 module ISO-9506-MMS-1 for the MMS abstract
  syntax; X.690 basic-encoding for the transfer syntax.
- **Confidence**: high for the reason codes and the provider reasons, which the clauses list; medium
  for the policy of accepting contexts; low for the identifiers 1 and 3, which are a choice.
- **Test**: `crates/igs-iso9506-mms-link/tests/upper.rs`, on the transport connection of D-016: the
  connection and its acceptance, each refusal, the release, the aborts from both ends, the transport
  lost or timed out, protocol errors, misuse, and the judgement of each context. Task L4 added the
  user data and the data transfer, and their tests.

### D-018 — The MMS application association (task L4)

- **Decision**: `association::Association` (crate `igs-iso9506-mms-link`) is a sans-I/O state machine
  that owns the presentation connection of D-017. It carries the ACSE APDUs and the MMS PDUs as the
  user data of the presentation connection, and negotiates the Initiate.
  - Carriage (ISO 9506-2 §A.1, §A.5, §24.1): the AARQ and AARE are the user data of the CP and CPA,
    in the ACSE context (identifier 1). The Initiate and its response are the user information of
    the AARQ and AARE, as an EXTERNAL whose indirect reference is the MMS context (identifier 3).
    After the association, each MMS PDU is the user data of a DATA TRANSFER in the MMS context.
  - Application context: `{iso standard 9506 part(2) mms-application-context-version1(5)}`
    (ISO 9506-2 §A.7). An AARQ with another one is refused with diagnostic 2.
  - Version: this end proposes 4, the minor version of ISO 9506-1 and ISO 9506-2 (ISO 9506-2 §24.11).
    The negotiated version is the lower of the proposed and 4; a proposal below 1 is refused.
  - Negotiation (ISO 9506-1 §8.2.1.1 and §8.2.1.2), by the responder:
    - each proposed outstanding limit is reduced to this end's limit of the configuration; a result
      of zero is refused, with class `max-services-outstanding-…-insufficient`;
    - an absent nesting level is unlimited; the level is reduced to this end's configured level,
      and a level below 2 is refused, class `nesting-level-insufficient`. The 2 is the TASE.2
      minimum (IEC 60870-6-702, stack requirements). This is a choice of this implementation;
    - the parameter CBBs are the intersection of those proposed and those served (§8.2.1.2.6);
    - the services called are the intersection of those proposed by the calling user and those
      this end serves (§8.2.1.1.8, §8.2.1.2.8); an empty intersection is refused, class
      `service-CBB-insufficient`. Refusing an association that serves nothing is a choice of this
      implementation.
    - A negative proposal is refused with class `other`.
  - Checks by the initiator: each negotiated value is within the proposal (versions, limits, nesting);
    a response that is not is a protocol error, and the association is aborted by the provider. The
    parameter CBBs and services of the response are reduced to those proposed, and any additional bit
    is ignored (ISO 9506-1 §8.2.1.1.8; task T3, D-022).
  - Refusal: an AARE with result rejected-permanent, diagnostic 1 (no reason given) or 2
    (application context not supported), and the Initiate-ErrorPDU of a failed negotiation as its user
    information. It travels as the user data of a CPR, the presentation user rejection (X.226
    §6.2.5.6). A refusal of the presentation or session provider is a `Refusal::Provider`.
  - Answer: the responder indicates the Initiate request, then the user accepts or rejects it. An
    accepted request is negotiated at once; a failed negotiation is refused with its error.
  - Data: a request (confirmed, unconfirmed, cancel) is checked against what the other end serves,
    a response against what this end serves (ISO 9506-1 §8.2.1.1.8). A received PDU the negotiation
    does not allow is passed up as `Unsupported`, for the Reject PDU of task L5. An Initiate PDU is
    refused within the association (ISO 9506-1 §8.2.2).
  - Conclude (ISO 9506-2 §24.3, Annex A.1.2), in the order of Annex A.1.2.1 (corrected in task L6):
    the initiator sends the CONCLUDE request alone, and sends ACSE's RLRQ, with the normal reason,
    only when the CONCLUDE response arrives. It waits for the RLRE, then requests the session release.
    The responder answers a CONCLUDE request at once with a CONCLUDE response (Annex A.1.2.2), and
    answers the RLRQ with a RLRE. It releases when the session release arrives. This end does not
    reject a CONCLUDE; the Conclude-ErrorPDU path is not implemented. The first version sent the RLRQ
    together with the request, which the reference peer did not answer; the interop scenario
    recorded it (`docs/capabilities.md`).
  - Abort (ISO 9506-2 §24.4): the MMS abort has no PDU of its own. It is the presentation abort
    with no user data (task L6: the empty ARU PPDU of the first version was dropped, because the
    User Data parameter is optional for a user abort, X.225 §8.3.9.6, and the empty PPDU is read as
    an MMS PDU of zero bytes by a dissector).
- **Known gaps**:
  - The services and parameter CBBs served are given by the caller (`Capabilities`). The TASE.2
    set is chosen with the client and server tasks, not here.
  - The version-dependent PDUs (ISO 9506-2 §7, "shall not appear in minor version 1 or 2") are not
    checked against the negotiated version.
  - The Conclude-ErrorPDU path is not implemented (see above).
- **Sources**: ISO 9506-1 §8.2 (Initiate service, §8.2.1, §8.2.2); ISO 9506-2 §8.2, §8.3, §24.1,
  §24.2, §24.3, §24.4, §24.11, Annex A (§A.1, §A.5, §A.7); ITU-T X.227 (AARQ, AARE, RLRQ, RLRE);
  X.226 §6.2.5.6; IEC 60870-6-702 stack requirements.
- **Confidence**: high for the carriage and the negotiation rules, which the clauses state; medium for
  the refusal of a nesting level below 2 and of an empty service set, which are choices; medium for the
  immediate answer to a CONCLUDE.
- **Test**: `crates/igs-iso9506-mms-link/tests/association.rs`, 19 tests on both roles: the negotiation
  of each value, the refusals with their classes, the services checked on send and receive, the
  conclude order of Annex A, the abort, and the time-out of a request with no answer.

### D-019 — Requests of the association: invoke IDs, limits, cancel, reject, timeouts

- **Decision**: `requests::Requests` (crate `igs-iso9506-mms-link`, module `requests`) owns the
  association of D-018 and carries the confirmed and unconfirmed requests. It takes the time as an
  argument, so that a test runs on a fake clock.
  - Invoke IDs: the requester gives each request an invoke ID not used by an outstanding one, from a
    counter that starts at 1 and wraps (ISO 9506-2 §7.1: unambiguous among the outstanding requests).
  - Limits: the negotiated values of the Initiate response are the outstanding limits by role
    (ISO 9506-1 §8.2.1.2.2, §8.2.1.2.3). The calling user creates the transactions of its requests
    with the calling limit, the called user with the called one. This end's own requests are limited
    by its role's value, and the requests of the other end by the other role's value. A request
    beyond the limit is refused on sending, and an incoming one beyond it is rejected with
    max-serv-outstanding-exceeded (ISO 9506-2 §8.6).
  - A repeated invoke ID of an incoming request is rejected as invalid (ISO 9506-2 §7.1).
  - Responses are matched by invoke ID and by the service: the tag of the choice of the request and
    of the response is the same for a service (ISO 9506-2 §7.1.1, §7.3.1). An unknown invoke ID, or
    another service, is rejected: a confirmed-response PDU with invalid-invokeID, and an error with
    the same reason for the confirmed-error PDU (ISO 9506-2 §6.3.1.1, §6.4).
  - Cancel (ISO 9506-2 §6.3.1.1, §6.3.1.2, §8.5). A requester cancels a request by its invoke ID; the
    request keeps its place until the cancel response and the request's final PDU have both arrived,
    in either order. A cancel that the other end accepts is the cancel response, then the error of
    the request with service-preempt and cancel (§6.3.1.2, transition 6). A cancel that is refused is
    a Cancel-ErrorPDU, and the request continues.
  - A cancel of an unknown request is answered with a Cancel-ErrorPDU and not indicated to the user
    (ISO 9506-2 §6.4).
  - A Reject PDU that names a request of this end ends it, when the rejected PDU was that request
    (confirmed-request category), or clears the cancel (cancel-request category). Other categories
    concern responses or errors this end sent, and change no state.
  - A request or unconfirmed PDU that the negotiation does not allow is answered with a Reject PDU,
    unrecognized-service (ISO 9506-1 §8.2.1.1.8).
  - Timeouts: a request outstanding for the request timeout of the configuration is reported once
    with `Timeout`. It stays outstanding and counts against the limit, and its response is still
    delivered. The layer never cancels it; the user decides. No clause of ISO 9506 gives a timeout
    behaviour, so this is a choice of this implementation.
  - Unconfirmed services are sent when the other end serves them, and keep no state.
- **Sources**: ISO 9506-2 §6.3.1, §6.3.1.1, §6.3.1.2, §6.4, §6.5, §7.1, §7.3, §8.5, §8.6; ISO 9506-1
  §8.2.1.1.8, §8.2.1.2.2, §8.2.1.2.3, and the Reject service of clause 7 that §6.5 refers to.
- **Confidence**: high for the invoke IDs, the matching and the cancel rules, which the clauses state;
  medium for the timeout behaviour, which is a choice.
- **Test**: `crates/igs-iso9506-mms-link/tests/requests.rs`, 17 tests on both roles, on a fake clock:
  the request and its response, the reuse of invoke IDs, an unknown or another response, the limits
  on both sides, the timeout reported once, the accepted and refused cancels, a cancel of an unknown
  request, the unconfirmed services, and the abort.

### D-020 — The transport driver on tokio (task T1)

- **Decision**: the client crate `igs-iso9506-mms` runs the transport connection of task L2 on tokio
  (`src/transport.rs`). A driver task owns the byte stream and the sans-I/O connection. The handle,
  `Transport`, exchanges TSDUs with the driver over two bounded channels of `CHANNEL_CAPACITY`
  (16 TSDUs) in each direction.
  - Stream: any `ByteStream` (`AsyncRead + AsyncWrite + Unpin + Send + 'static`). TCP is one, through
    `connect_tcp`, which sets `TCP_NODELAY`; TLS will be another (task X1). The tests use an in-memory
    duplex stream as the network.
  - Back-pressure: a sender waits while its channel is full. The driver stops reading the stream
    while it cannot deliver a TSDU, so the flow control of the stream reaches the peer. A caller that
    sends and receives in the same task must receive concurrently, or it waits.
  - Connect: the initiator's connect timer is the connect timeout of the configuration, on the tokio
    clock; `connect_tcp` also runs its TCP connect within it. The responder has no timer, as in
    task L2. Expiry is `ConnectTimeout`.
  - Shutdown: `Transport::shutdown` drops the outbound channel. The TSDUs already sent are written,
    then the connection is released: class 0 releases implicitly, with the network connection
    (X.224 §5.4.4), so the stream is shut down and nothing is sent for the release. TSDUs received
    and not yet taken are discarded. The return value is the reason the driver stopped, when it
    stopped with an error.
  - Errors: a stream failure is `Io`; a peer's end of stream is `PeerClosed`; a transport closure
    keeps its cause from L2 (`Closed`); a driver that has stopped returns `Stopped` to a sender. A
    reconnect policy is for task T2.
  - Read buffer: 8192 octets. TCP port 102 (RFC 1006) is the caller's choice.
- **Dependency**: `tokio` 1 (MIT), with the features of `igs-iec104`: `io-util`, `macros`, `net`,
  `rt`, `sync`, `time`; `test-util` in the development dependencies, for the paused clock. Its
  transitive crates (`bytes`, `mio`, `libc`, `socket2`, `pin-project-lite`, `tokio-macros`,
  `proc-macro2`, `quote`, `syn`, `unicode-ident`) are MIT, Apache-2.0 or Unicode-3.0, as
  `cargo deny check` reports. The reason: the MMS client needs an asynchronous runtime, and the same
  runtime is already the choice of `igs-iec104`.
- **Sources**: ITU-T X.224 §5.4.4 (implicit release in class 0); RFC 1006 (TCP port 102), as in
  D-015.
- **Confidence**: high for the behaviour, which the loopback tests check on the stream and on the
  paused clock; medium for the capacity of 16, which is an operational choice to revisit with the
  bench.
- **Test**: `crates/igs-iso9506-mms/tests/loopback.rs`, 11 tests: both directions, many TSDUs in order,
  a 200 000-octet TSDU, an empty TSDU, a clean shutdown seen by the peer, the TSDUs written before
  the release, a slow receiver holding back the sender, the connect timeout on the paused clock, a
  peer that closes, a responder that declines, and an invalid configuration.

### D-021 — The client API: connection, queue, events, reconnection, close (task T2)

- **Decision**: `Client` (crate `igs-iso9506-mms`, module `client`) is a handle on a background task
  (`actor.rs`) that owns the connection, the association and the requests of the link crate. The
  task waits on three things at once: the calls, the TSDUs of the connection, and a one-second tick
  that checks the request timeouts and the close.
  - Services: `request` takes any confirmed request of the codec. The services in scope (the table of
    the profile, `in_scope`) have typed methods: `identify`, `get_name_list`, `read`, `write`,
    `get_variable_access_attributes`, `define_named_variable_list`, `get_named_variable_list_attributes`,
    `delete_named_variable_list`. An answer of another service is `Unexpected`.
  - Events: `Event::State` (connected, disconnected, reconnecting with the attempt number, closed) and
    `Event::Report` (an information report). The first event is `Connected`.
  - Back-pressure, documented in the client: a call waits while the command channel is full (its
    capacity is `command_capacity`), and requests beyond the outstanding limit wait in a queue of the
    same capacity; the event channel holds `event_capacity` events, and the task waits on it, so
    that reports are never dropped.
  - Outstanding limit: the requests are issued as the limit of the association allows (see D-019).
  - Timeouts: a request with no answer within the request timeout of the configuration fails with
    `Timeout`. The request stays outstanding in the link layer, so it still counts against the limit,
    and a late answer is ignored. A peer that never answers blocks the requests at the limit; the
    caller closes or reconnects.
  - Reconnection: `Reconnect::Backoff { initial, max, attempts }`, doubling the delay up to `max`.
    The default is 1 s to 30 s, with no bound on the attempts. `Reconnect::Never` closes the client.
    A connection that ends fails the calls in flight with `ConnectionLost`; calls made while
    reconnecting fail the same way. Each reconnection opens a new association with the same proposal.
  - Close: the CONCLUDE request is sent, then the release is awaited. If the peer does not confirm it
    within the request timeout, the association is aborted. This is the decision recorded for the gap G1
    of `docs/capabilities.md`: the peer does not answer the ACSE release, and Annex A makes the
    release a requirement, so the client falls back to the abort instead of waiting forever.
  - An indicated request that the client does not serve is rejected as unrecognized-service (ISO 9506-1
    §8.2.1.1.8).
- **Sources**: ISO 9506-1 §8.2 (Initiate), §8.2.1.1.8; ISO 9506-2 §6.3, §7, §8.5, §8.6, §24.3 and
  Annex A.1.2; the services of the profile table (`in_scope`).
- **Confidence**: high for the services, the events and the queue, which the tests check; medium for
  the reconnection defaults and the one-second tick, which are operational choices; medium for the close
  fallback, which is a choice pending the peer's behaviour (G1).
- **Test**: `crates/igs-iso9506-mms/tests/client.rs`, 16 tests against a loopback server built from the
  link layers: one per service in scope and the identify, the service error, the event of a report, the
  queue at the limit, the close, the reconnection with the call in flight, no reconnection, a refused
  association, and the timeout on a paused clock.

### D-022 — The command line client, and the interoperability found by it (task T3)

- **Decision**:
  - `igsmms-client` (`src/bin/igsmms-client.rs`) is a command line over the client API: `identify`,
    `names`, `read`, `write`, `attributes`. `--trace` prints the decoded actions on standard error;
    `--server`, `--timeout` and `--nesting` set the connection. Errors exit with status 1; a usage
    error with status 2.
  - Dependency `clap` 4 (MIT or Apache-2.0), with the derive feature only and no default features,
    for the command line. Its transitive crates are the same licences, as `cargo deny` reports.
  - The initiator reduces the peer's answer to the proposal: the parameter CBBs and the services that
    are not proposed are ignored, as ISO 9506-1 §8.2.1.1.8 says (G7). Before, the association was
    refused; the reference server does set `status`, which was not proposed.
  - An answer that the negotiation does not allow (for example, data nested deeper than negotiated) is
    rejected with a Reject PDU (ISO 9506-2 §6.4), and the caller is told at once, instead of waiting
    for its timeout.
  - `Client::abort` ends the association at once. The command line uses it after an error, because the
    orderly close waits for a release that the reference server does not confirm (G1).
  - The parameter CBBs proposed can be taken as negotiated for the outgoing checks, by the option
    `ClientConfig::lenient_parameter_cbbs` and the flag `--lenient-parameter-cbbs`. It is off by
    default: the standard's negotiation is the rule (G8).
  - The command line proposes a nesting level of 6 by default (`--nesting`). The TASE.2 minimum of 2
    of D-015 stays the library default; the reference server returns data deeper than 2 (G10).
- **Sources**: ISO 9506-1 §8.2.1.1.8 (extra bits ignored), §8.2.1.2; ISO 9506-2 §6.4 (Reject of an
  invalid PDU), §7.5.2 (identifiers of 32 characters, and the gap G9), §8.1.3 (CBBs); the reference
  transcript of `docs/ai-log/T3.md`.
- **Confidence**: high for the reduction of the answer and the Reject, which the clauses state; medium
  for the lenient option, which is a deliberate departure from the standard for interoperability with
  a non-conformant server; high for the observations, which are the transcript.
- **Test**: `crates/igs-iso9506-mms-link/src/association.rs` (two unit tests: the extra bits ignored,
  a value above the proposal refused), and the binary's own unit tests (the command line is valid, value
  parsing, the display of data, the domains of names).

### D-023 — An unconfirmed PDU is checked against the end that sends it (task T4)

- **Decision**: the CBB check of a PDU names the end that serves it. A request is served by the end that
  receives it; a response, and an unconfirmed PDU such as the information report, by the end that sends
  it. An incoming report is therefore checked against the peer's view (its negotiated CBBs, or the
  proposed ones with the lenient option), and an outgoing one against this end's.
- **Why**: the matrix of T4 found that the reference server's report (`variableListName`, which needs the
  `vlis` CBB) was rejected with `unrecognized-service`. The check used this end's view for every unconfirmed
  PDU, so the server's CBBs were never consulted for its reports. The rule now follows the sender.
- **Sources**: ISO 9506-2 §8.2 (services and CBBs of the information report), ISO 9506-1 §8.2.1.1.8 for
  the services each end provides. The reference transcript of `docs/ai-log/T4.md`.
- **Confidence**: high for the principle (the report is a service of the server); medium for the
  reading that the `services` bit of an unconfirmed service is the sender's, which the reference server
  supports (its `servicesSupportedCalled` sets `informationReport`).
- **Test**: `crates/igs-iso9506-mms-link/src/association.rs` (the unit tests `an_incoming_report_is_checked_against_the_servers_cbbs` and
  `a_request_is_checked_against_the_end_that_serves_it`), and
  `crates/igs-iso9506-mms-link/tests/requests.rs` (`an_unconfirmed_service_the_peer_does_not_serve_is_not_sent`,
  now sent by the responder).

### D-024 — The client matrix: Rust scenarios, checked by the bench (task T4)

- **Decision**: one Rust scenario per row of the matrix, in `crates/igs-iso9506-mms/tests/interop_matrix.rs`,
  driving the client API with the lenient option where the reference server needs it (G8) and the
  conformant default where the row shows the refusal. `bench/tests/test_t4_client_matrix.py` starts the
  reference server and a capture, runs the scenarios, and checks the capture in tshark: every confirmed
  service in scope, and the information report, on the wire, with no malformed frame.
- **Why**: the scenarios need the client API (the `define`, `get` and `delete` of named variable lists have
  no command of the CLI), and tshark is the independent decoder of the bench.
- **Scope of the matrix**: the nine services in scope. The reference server is the only peer; the
  stack as server (S4) and the reverse direction (G2) are not in T4.
- **Recorded gaps**: `docs/capabilities.md`, G8, G9, G12 (domain-scope lists refused by the reference
  server), G1 (release unconfirmed).
- **Confidence**: high for the observations, which are the captured traffic.
- **Test**: the matrix itself, with the bench test above.

## Third-party code and sources

| Source | Licence | Use | Provenance |
| --- | --- | --- | --- |
| tokio 1.54.1 and its dependencies | MIT, Apache-2.0, Unicode-3.0 (see `cargo deny check`) | Asynchronous runtime and TCP of the client crate (D-020) | crates.io; no source read beyond its public API |
| libiec61850 | GPL-3.0 (`COPYING`, GitHub licence metadata) | Reference peer of the bench, tag `v1.6.2.1`, commit `c28c27c`, black box only; image built locally, not distributed | Source never read |
