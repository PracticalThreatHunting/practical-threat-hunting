from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class DomainCandidate:
    raw_value: str
    parsed_input: str
    display_value: str
    ascii_fqdn: str
    registrable_domain: str
    labels: tuple[str, ...]
    source_id: str
    source_record_id: str
    collected_at: datetime
    normalized_at: datetime
    normalizer_version: str

def normalize_candidate(raw_value, source_id, source_record_id, collected_at,
                        normalized_at, to_idna2008_ascii,
                        registrable_domain_from_psl, normalizer_version):
    # raw_value is the decoded string supplied to this function. Retain original
    # bytes or their hash, encoding, and decode policy before calling it when
    # byte-level fidelity is required.
    parsed_input = raw_value.strip()
    display_value = parsed_input[:-1] if parsed_input.endswith(".") else parsed_input
    ascii_fqdn = to_idna2008_ascii(display_value).lower()
    if not ascii_fqdn or ".." in ascii_fqdn:
        raise ValueError("invalid normalized domain")
    return DomainCandidate(
        raw_value=raw_value,
        parsed_input=parsed_input,
        display_value=display_value,
        ascii_fqdn=ascii_fqdn,
        registrable_domain=registrable_domain_from_psl(ascii_fqdn),
        labels=tuple(ascii_fqdn.split(".")),
        source_id=source_id,
        source_record_id=source_record_id,
        collected_at=collected_at,
        normalized_at=normalized_at,
        normalizer_version=normalizer_version,
    )
