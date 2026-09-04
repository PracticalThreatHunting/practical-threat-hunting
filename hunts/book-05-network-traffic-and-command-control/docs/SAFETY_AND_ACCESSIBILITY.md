# Safety and accessibility

## Authorized, file-only use

Run this lab only on the included synthetic files and on systems you are
authorized to use. Do not adapt it into a traffic generator, replay the capture
onto a network, connect it to a live interface, or substitute production packet
captures without a separate written authorization, privacy assessment, and
retention plan.

The shared PCAP contains inert protocol examples: DNS, a complete HTTP exchange,
SSH identification banners without authentication or commands, ICMP echo bytes,
and a benign GRE-encapsulated datagram. The generator writes the PCAP directly
as a file and opens no socket. Fixture IP addresses and names use private,
documentation, example, or special-use space.

Queries identify bounded suspicious shapes. They do not establish intent,
compromise, attribution, or maliciousness. Validate time coverage, parser
quality, counter semantics, NAT/VPN identity, policy effective dates, and lawful
visibility before escalating a candidate.

## Data handling

- Keep raw and canonical records together so missing or derived evidence remains
  reviewable.
- Do not commit credentials, live identifiers, customer data, decrypted content,
  or private certificate material.
- Write ad hoc reports outside the checkout with `BOOK5_REPORT_DIR`.
- Remove temporary environments and reports according to local policy; the
  verifier does not perform destructive cleanup outside its own temporary dirs.

## Accessible use

All authoritative outputs are available as UTF-8 SQL, JSON, JSONL, Markdown, or
JUnit XML. Meaning does not depend on color, animation, hover state, audio, or an
image. Tables have textual headers; status values are written as words; commands
can be copied from fenced text. Filenames use stable numeric hunt identifiers.

For low-vision or screen-reader workflows, begin with the fixture manifests in
`fixtures/manifests/`, then review `reports/verification.json` after running the
verifier. Both are textual and require no visual chart interpretation. Long
JSONL lines are machine artifacts—use the manifests and formatted verification
report for human review.
