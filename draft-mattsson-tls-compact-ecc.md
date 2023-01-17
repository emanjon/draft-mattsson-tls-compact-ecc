---
title: "Compact ECDHE and ECDSA Encodings for TLS 1.3"
abbrev: "Compact ECDSA and ECDHE"
category: std

docname: draft-mattsson-tls-compact-ecc-latest
submissiontype: IETF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Transport Layer Security"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Transport Layer Security"
  type: "Working Group"
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "emanjon/draft-mattsson-tls-compact-ecc"
  latest: "https://emanjon.github.io/draft-mattsson-tls-compact-ecc/draft-mattsson-tls-compact-ecc.html"

author:
- initials: J.
  surname: Preuß Mattsson
  name: John Preuß Mattsson
  org: Ericsson AB
  abbrev: Ericsson
  street: SE-164 80 Stockholm
  country: Sweden
  email: john.mattsson@ericsson.com

normative:

  RFC2119:
  RFC5480:
  RFC8174:
  RFC8446:
  RFC8447:
  RFC8447:
informative:

  RFC6090:
  RFC9147:
  I-D.ietf-tls-ctls:

  SECG:
    target: https://www.secg.org/sec1-v2.pdf
    title: Standards for Efficient Cryptography 1 (SEC 1)
    date: May 2009

  SafeCurves:
    target: https://safecurves.cr.yp.to/twist.html
    title: "SafeCurves: choosing safe curves for elliptic-curve cryptography"
    date: January 2017

  SP-800-56A:
    target: https://doi.org/10.6028/NIST.SP.800-56Ar3
    title: Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography
    seriesinfo:
      "NIST": "Special Publication 800-56A Revision 3"
    author:
      -
        ins: E. Barker
      -
        ins: L. Chen
      -
        ins: A. Roginsky
      -
        ins: A. Vassilev
      -
        ins: R. Davis
    date: April 2018

--- abstract

The encodings used in the ECDHE groups secp256r1, secp384r1, and secp521r1 and the ECDSA signature algorithms ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, and ecdsa_secp521r1_sha512 have significant overhead and the ECDSA encoding produces variable-length signatures. This document defines new optimal fixed-length encodings and registers new ECDHE groups and ECDSA signature algorithms using these new encodings. The new encodings reduce the size of the ECDHE groups with 33, 49, and 67 bytes and the ECDSA algorithms with an average of 7 bytes. These new encodings also work in DTLS 1.3 and are especially useful in cTLS.


--- middle

# Introduction

The encodings used in the ECDHE groups secp256r1, secp384r1, and secp521r1 and the ECDSA signature algorithms ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, and ecdsa_secp521r1_sha512 have significant overhead and the ECDSA encodings produces variable-length signatures. This document defines new optimal fixed-length encodings and registers new ECDHE groups and ECDSA signature algorithms using these new encodings. The new encodings reduce the size of the ECDHE groups with 33, 49, and 67 bytes and the ECDSA algorithms with an average of 7 bytes. These new encodings also work in DTLS 1.3 {{RFC9147}} and are especially useful in cTLS {{I-D.ietf-tls-ctls}}. When secp256r1 and ecdsa_secp256r1_sha256 are used as a replacement for the the old encdodings they reduce the size of the TLS handshake with on average 80 bytes.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Compact ECDHE Encoding

The encoding of the ECDHE groups secp256r1, secp384r1, and secp521r1 have significant overhead. This document specifies a new optimal fixed-length encoding for the groups. The new encoding is defined as a compression of the UncompressedPointRepresentation structure. Given a UncompressedPointRepresentation structure {{RFC8446}}

~~~~~~~~~~~~~~~~~~~~~~~
      struct {
          uint8 legacy_form = 4;
          opaque X[coordinate_length];
          opaque Y[coordinate_length];
      } UncompressedPointRepresentation;
~~~~~~~~~~~~~~~~~~~~~~~

the legacy_form and Y field are omitted to create a CompactRepresentation structure.

~~~~~~~~~~~~~~~~~~~~~~~
      struct {
          opaque X[coordinate_length];
      } CompactRepresentation;
~~~~~~~~~~~~~~~~~~~~~~~

The resulting groups are called secp256r1_compact, secp384r1_compact, and secp521r1_compact. The new encodings have CompactRepresentation structures of length 32, 48, and 66 bytes, and reduce the size with 33, 49, and 67 bytes respectively. For secp256r1_compact, secp384r1_compact, and secp521r1_compact the opaque key_exchange field contains the serialized value of the CompactRepresentation struct:

| Value | Description | Recommended | Reference |
| TBD1 | secp256r1_compact | Y | [This-Document] |
| TBD2 | secp384r1_compact | Y | [This-Document] |
| TBD3 | secp521r1_compact | Y | [This-Document] |
{: #ecdhe-table title="Compact ECDHE Groups" cols="r l r l"}

## Example Compact ECDHE Encoding

The following shows an example compact ECDHE encoding. {{ecdhe-old}} shows a 65 bytes ecdsa_secp256r1_sha256 UncompressedPointRepresentation structure.

~~~~~~~~~~~~~~~~~~~~~~~
          04 A6 DA 73 92 EC 59 1E 17 AB FD 53 59 64 B9 98
          94 D1 3B EF B2 21 B3 DE F2 EB E3 83 0E AC 8F 01
          51 81 26 77 C4 D6 D2 23 7E 85 CF 01 D6 91 0C FB
          83 95 4E 76 BA 73 52 83 05 34 15 98 97 E8 06 57
          80
~~~~~~~~~~~~~~~~~~~~~~~
{: #ecdhe-old title="secp256r1"}

{{ecdhe-new}} shows the 32 bytes secp256r1_compact CompactRepresentation structure encoding of the same key share.

~~~~~~~~~~~~~~~~~~~~~~~
          A6 DA 73 92 EC 59 1E 17 AB FD 53 59 64 B9 98 94
          D1 3B EF B2 21 B3 DE F2 EB E3 83 0E AC 8F 01 51
~~~~~~~~~~~~~~~~~~~~~~~
{: #ecdhe-new title="secp256r1_compact"}

## Implementation Considerations for Compact Representation

For compatibility with APIs a compressed y-coordinate might be required. For validation or for compatibility with APIs that do not support the full {{SECG}} format an uncompressed y-coordinate might be required (using the notation in {{SECG}}):

* If a compressed y-coordinate is required, then the value ~yp set to zero can be used. The compact representation described above can in such a case be transformed into the SECG point compressed format by prepending X with the single byte 0x02 (i.e., M = 0x02 \|\| X).
* If an uncompressed y-coordinate is required, then a y-coordinate has to be calculated following Section 2.3.4 of {{SECG}} or Appendix C of {{RFC6090}}. Any of the square roots (see {{SECG}} or {{RFC6090}}) can be used. The uncompressed SECG format is M = 0x04 \|\| X \|\| Y.

For example: The curve P-256 has the parameters (using the notation in {{RFC6090}})

* p = 2<sup>256</sup> − 2<sup>224</sup> + 2<sup>192</sup> + 2<sup>96</sup> − 1
* a = -3
* b = 410583637251521421293261297800472684091144410159937255
54835256314039467401291

Given an example x:

* x = 115792089183396302095546807154740558443406795108653336
398970697772788799766525

we can calculate y as the square root w = (x<sup>3</sup> + a {{{⋅}}} x + b)<sup>((p + 1)/4)</sup> (mod p)

* y = 834387180070192806820075864918626005281451259964015754
16632522940595860276856

Note that this does not guarantee that (x, y) is on the correct elliptic curve. A full validation according to Section 5.6.2.3.3 of {{SP-800-56A}} can be achieved by also checking that 0 {{{≤}}} x < p and that y<sup>2</sup> {{{≡}}} x<sup>3</sup> + a {{{⋅}}} x + b (mod p).

# Compact ECDSA Encoding

The variable-length encoding of the ECDSA signature algorithms ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, and ecdsa_secp521r1_sha512 specified in {{RFC8446}} have significant overhead.

This document specifies a new optimal fixed-length encoding for the algorithms. The new encoding is defined as a compression of the DER-encoded ECDSA-Sig-Value structure. Given a DER-encoded ECDSA-Sig-Value structure {{RFC5480}}

~~~~~~~~~~~~~~~~~~~~~~~
      Ecdsa-Sig-Value ::= SEQUENCE {
          r       INTEGER,
          s       INTEGER
      }
~~~~~~~~~~~~~~~~~~~~~~~

the SEQUENCE type, INTEGER type, and length fields are omitted and if necessary the two INTEGER value fields are truncated (at most a single zero byte) or left padded with zeroes to the fixed length L. For secp256r1, secp384r1, and secp521r1, L is 32, 48, and 66 bytes respectively. The resulting signatures are called ecdsa_secp256r1_sha256_compact, ecdsa_secp384r1_sha384_compact, and ecdsa_secp521r1_sha512_compact and has length 64, 96, and 132 bytes respectively. The new encodings reduce the size of the signatures with an average of 7 bytes. For secp256r1_compact, secp384r1_compact, and secp521r1_compact the opaque signature field contains the compressed Ecdsa-Sig-Value.

| Value | Description | Recommended | Reference |
| TBD4 | ecdsa_secp256r1_sha256_compact | Y | [This-Document] |
| TBD5 | ecdsa_secp384r1_sha384_compact | Y | [This-Document] |
| TBD6 | ecdsa_secp521r1_sha512_compact | Y | [This-Document] |
{: #ecdsa-table title="Compact ECDSA Signature Algorithms" cols="r l r l"}

## Example Compact ECDSA Encoding

The following shows an example compact ECDSA encoding. {{ecdsa-old}} shows a 71 bytes DER encoded ecdsa_secp256r1_sha256 ECDSA-Sig-Value structure. The values on the left are the ASN.1 tag (in hexadecimal) and the length (in decimal).

~~~~~~~~~~~~~~~~~~~~~~~
30  69: SEQUENCE {
02  33:  INTEGER
          00 D7 A4 D3 4B D5 4F 55 FE E1 A8 96 25 67 8C 3D
          D5 E5 F6 0D AC 73 EC 94 0C 5C 7B 93 04 A0 20 84
          A9
02  32:  INTEGER
          28 9F 59 5E D4 88 B9 AC 68 9A 3D 19 2B 1A 8B B3
          8F 34 AF 78 74 C0 59 C9 80 6A 1F 38 26 93 53 E8
          }
~~~~~~~~~~~~~~~~~~~~~~~
{: #ecdsa-old title="ecdsa_secp256r1_sha256"}

{{ecdsa-new}} shows the 64 bytes ecdsa_secp256r1_sha256_compact encoding of the same signature.

~~~~~~~~~~~~~~~~~~~~~~~
          D7 A4 D3 4B D5 4F 55 FE E1 A8 96 25 67 8C 3D D5
          E5 F6 0D AC 73 EC 94 0C 5C 7B 93 04 A0 20 84 A9
          28 9F 59 5E D4 88 B9 AC 68 9A 3D 19 2B 1A 8B B3
          8F 34 AF 78 74 C0 59 C9 80 6A 1F 38 26 93 53 E8
~~~~~~~~~~~~~~~~~~~~~~~
{: #ecdsa-new title="ecdsa_secp256r1_sha256_compact"}


# Security Considerations

Compact representation of a ECDHE key share produces the same shared secret as the uncompressed encoding and does not change any requirements on point validation. Using compact representation has some security benefits. As described in {{SafeCurves}} it helps to protect against invalid-curve attacks as an implementation will naturally detect invalid inputs when it reconstructs the missing coordinate. As not even the sign of the y-coordinate is encoded, compact representation trivially avoids so called "benign malleability" attacks where an attacker changes the sign, see {{SECG}}.


# IANA Considerations

IANA is requested to update the TLS Supported Groups registry {{RFC8447}} under the Transport Layer Security (TLS) Parameters heading with the contents of {{ecdhe-table}}.

IANA is requested to update the TLS SignatureScheme registry {{RFC8447}} under the Transport Layer Security (TLS) Parameters heading with the contents of {{ecdsa-table}}.

--- back

# Acknowledgments
{:numbered="false"}

The authors want to thank {{{Scott Fluhrer}}} and {{{Erik Thormarker}}} for their valuable comments and feedback.
