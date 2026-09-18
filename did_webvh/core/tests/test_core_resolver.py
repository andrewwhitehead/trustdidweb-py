import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from did_webvh.core.file_utils import AsyncTextGenerator, AsyncTextReadError, read_str
from did_webvh.core.resolver import (
    DereferencingResult,
    DidResolver,
    HistoryResolver,
    HistoryVerifier,
    ResolutionResult,
    dereference_fragment,
    normalize_services,
    reference_map,
)


class MockHistoryResolver(HistoryResolver):
    def __init__(
        self,
        entry_log: str,
        witness_log: str | None = None,
    ):
        """Constructor."""
        self.entry_log = entry_log
        self.witness_log = witness_log

    def resolve_entry_log(self, _document_id: str) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        return read_str(self.entry_log)

    def resolve_witness_log(self, _document_id: str) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        return read_str(self.witness_log or "")


class MockHistoryVerifier(HistoryVerifier):
    def __init__(self, **kwargs):
        super().__init__(verify_proofs=False, **kwargs)


mock_document = {
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/multikey/v1",
        "https://identity.foundation/.well-known/did-configuration/v1",
        "https://identity.foundation/linked-vp/contexts/v1",
    ],
    "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
    "authentication": [
        "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    ],
    "service": [
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com%3A5000",
        },
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#whois",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://example.com%3A5000/whois.vp",
        },
    ],
    "verificationMethod": [
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
            "controller": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
            "type": "Multikey",
            "publicKeyMultibase": "z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
        }
    ],
    "assertionMethod": [
        "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    ],
}

# async def test_generate_history():
#     from did_webvh.core.state import DocumentState

#     state1 = DocumentState.initial({"method": "testmethod"}, '{"id": "docid-{SCID}"}')
#     state2 = state1.create_next(None)
#     history = [state1.history_line(), state2.history_line()]
#     print(history)


async def test_resolve_history():
    HISTORY = [
        {
            "versionId": "1-QmV2AdEkGSvn3K5v7x73rFVMrhVxAUbDdPRhx2fmVRFpdE",
            "versionTime": "2025-01-20T23:46:33Z",
            "parameters": {
                "method": "testmethod",
                "scid": "QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH",
            },
            "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
            "proof": [],
        },
        {
            "versionId": "2-QmdFY1RaW7oKFewnFo1T9w6Y2nn5VSUGTYQYYF2wsEe9rE",
            "versionTime": "2025-01-20T23:46:34Z",
            "parameters": {},
            "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
            "proof": [],
        },
    ]
    history = MockHistoryResolver("\n".join(map(json.dumps, HISTORY)))
    resolver = DidResolver(MockHistoryVerifier())
    res = await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert isinstance(res, ResolutionResult)
    assert isinstance(res.document, dict)
    assert res.document_metadata["versionId"].startswith("2-")

    res = await resolver.resolve("bad-docid", history)
    assert res.document is None
    assert res.resolution_metadata["error"] == "invalidDid"
    assert res.resolution_metadata["problemDetails"]["type"].endswith(
        "#did-log-id-mismatch"
    )


async def test_resolve_history_rejects_non_monotonic_version_time():
    HISTORY = [
        {
            "versionId": "1-QmV2AdEkGSvn3K5v7x73rFVMrhVxAUbDdPRhx2fmVRFpdE",
            "versionTime": "2025-01-20T23:46:33Z",
            "parameters": {
                "method": "testmethod",
                "scid": "QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH",
            },
            "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
            "proof": [],
        },
        {
            "versionId": "2-QmaofgPQBFQBEX9dFjsYsJXTgmMhZoEXwfNegVZ38rQ7YX",
            "versionTime": "2025-01-20T23:46:33Z",
            "parameters": {},
            "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
            "proof": [],
        },
    ]
    history = MockHistoryResolver("\n".join(map(json.dumps, HISTORY)))
    resolver = DidResolver(MockHistoryVerifier())
    res = await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert res.document is None
    assert res.resolution_metadata["error"] == "invalidDid"
    assert res.resolution_metadata["problemDetails"]["detail"] == (
        "versionTime for version '2' must be greater than previous entry time"
    )


FUTURE_HISTORY = [
    {
        "versionId": "1-QmV2AdEkGSvn3K5v7x73rFVMrhVxAUbDdPRhx2fmVRFpdE",
        "versionTime": "2025-01-20T23:46:33Z",
        "parameters": {
            "method": "testmethod",
            "scid": "QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH",
        },
        "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
        "proof": [],
    },
    {
        "versionId": "2-QmNabRHT8ykrWfePhqBV1zWgMAKwAn665ja8V8hekJ3pnH",
        "versionTime": "2099-01-01T00:00:00Z",
        "parameters": {},
        "state": {"id": "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH"},
        "proof": [],
    },
]


@pytest.mark.parametrize(
    "resolution_time,future_skew",
    [
        # default: the actual current time
        (None, None),
        # 10 minutes before versionTime, beyond the default 5 minute skew
        (datetime(2098, 12, 31, 23, 50, tzinfo=timezone.utc), None),
        # naive datetimes are treated as UTC
        (datetime(2098, 12, 31, 23, 50), None),
        # a custom skew
        (datetime(2098, 12, 31, 23, 59, tzinfo=timezone.utc), timedelta(seconds=30)),
    ],
)
async def test_resolve_history_rejects_future_version_time(resolution_time, future_skew):
    history = MockHistoryResolver("\n".join(map(json.dumps, FUTURE_HISTORY)))
    resolver = DidResolver(
        MockHistoryVerifier(resolution_time=resolution_time, future_skew=future_skew)
    )
    res = await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert res.document is None
    assert res.resolution_metadata["error"] == "invalidDid"
    skew = "30 seconds" if future_skew else "5 minutes"
    assert res.resolution_metadata["problemDetails"]["detail"] == (
        f"versionTime for version '2' must not be more than {skew} in the future"
    )


@pytest.mark.parametrize(
    "resolution_time,future_skew",
    [
        # within the default 5 minute skew
        (datetime(2098, 12, 31, 23, 56, tzinfo=timezone.utc), None),
        # within a larger custom skew
        (datetime(2098, 12, 31, 23, 50, tzinfo=timezone.utc), timedelta(minutes=15)),
        # after versionTime
        (datetime(2099, 6, 1, tzinfo=timezone.utc), timedelta(0)),
    ],
)
async def test_resolve_history_accepts_version_time_within_skew(
    resolution_time, future_skew
):
    history = MockHistoryResolver("\n".join(map(json.dumps, FUTURE_HISTORY)))
    resolver = DidResolver(
        MockHistoryVerifier(resolution_time=resolution_time, future_skew=future_skew)
    )
    res = await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert res.document is not None, res.resolution_metadata
    assert res.document_metadata["versionId"].startswith("2-")
    assert res.document_metadata["versionTime"] == "2099-01-01T00:00:00Z"


@pytest.mark.parametrize(
    "resolution_time", [None, datetime(2099, 6, 1, tzinfo=timezone.utc)]
)
async def test_resolve_history_uses_a_fixed_resolution_time(resolution_time):
    seen = []

    class RecordingVerifier(MockHistoryVerifier):
        def verify_state(self, *args):
            seen.append(self._resolution_time)
            return super().verify_state(*args)

    history = MockHistoryResolver("\n".join(map(json.dumps, FUTURE_HISTORY)))
    verifier = RecordingVerifier(resolution_time=resolution_time)
    resolver = DidResolver(verifier)
    await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert len(seen) == 2
    assert seen[0] is not None
    assert seen[0] is seen[1]
    assert seen[0] is verifier._resolution_time
    if resolution_time:
        assert seen[0] is resolution_time


def test_history_verifier_rejects_negative_future_skew():
    with pytest.raises(ValueError, match="future_skew"):
        HistoryVerifier(future_skew=timedelta(minutes=-1))


async def test_resolve_history_future_version_time_not_enforced():
    history = MockHistoryResolver("\n".join(map(json.dumps, FUTURE_HISTORY)))
    resolver = DidResolver(
        HistoryVerifier(verify_proofs=False, enforce_future_skew=False)
    )
    res = await resolver.resolve(
        "docid-QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH", history
    )
    assert res.document is not None, res.resolution_metadata
    assert res.document_metadata["versionId"].startswith("2-")


async def test_resolve_history_failed_request():
    class BadResolver(HistoryResolver):
        def resolve_entry_log(self, _document_id: str) -> AsyncTextGenerator:
            """Resolve the entry log file for a DID."""
            raise AsyncTextReadError("read error")

    resolver = DidResolver(MockHistoryVerifier())
    res = await resolver.resolve("docid", BadResolver())
    assert isinstance(res, ResolutionResult)
    assert res.document is None
    assert res.resolution_metadata["error"] is not None


def test_reference_map():
    result = reference_map(mock_document)
    assert isinstance(result, dict)

    # Use dict instead of list
    services_in_dict_document = deepcopy(mock_document)
    services_in_dict_document["service"] = {
        "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com%3A5000",
    }
    reference_map(services_in_dict_document)

    # id isn't a string
    bad_id_document = deepcopy(mock_document)
    bad_id_document["id"] = 123
    with pytest.raises(ValueError):
        reference_map(bad_id_document)


def test_normalize_services():
    result = normalize_services(mock_document)
    assert isinstance(result, list)

    # Service isn't a dict
    bad_service_document = deepcopy(mock_document)
    bad_service_document["service"] = [
        '{"id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain","type": "LinkedDomains","serviceEndpoint": "https://example.com%3A5000"}'
    ]

    with pytest.raises(ValueError):
        normalize_services(bad_service_document)

    # Service doesn't contain # symbol
    no_hash_symbol_document = deepcopy(mock_document)
    no_hash_symbol_document["service"] = [
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
            "type": "LinkedDomains",
            "serviceEndpoint": "https://example.com%3A5000",
        },
        {
            "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
            "type": "LinkedVerifiablePresentation",
            "serviceEndpoint": "https://example.com%3A5000/whois.vp",
        },
    ]

    with pytest.raises(ValueError):
        normalize_services(no_hash_symbol_document)

    # Services are in a dict instead of list
    services_in_dict_document = deepcopy(mock_document)
    services_in_dict_document["service"] = {
        "id": "did:webvh:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
        "type": "LinkedDomains",
        "serviceEndpoint": "https://example.com%3A5000",
    }

    normalize_services(services_in_dict_document)


def test_dereference_fragment():
    result = dereference_fragment(
        mock_document, "#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    )
    assert isinstance(result, DereferencingResult)
    result = dereference_fragment(mock_document, "#domain")
    assert isinstance(result, DereferencingResult)

    # This ref doesn't exist
    result = dereference_fragment(
        mock_document, "#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAz"
    )
    assert isinstance(result, DereferencingResult)
    assert result.dereferencing_metadata.get("error") is not None


async def test_resolve_history_terminates_on_an_empty_log():
    """An empty entry log must report `#missing-log`, not spin.

    `resolve_state` primes a two-line lookahead with `if not state: continue`. When the log holds
    no entries, `state` is never assigned and `StopAsyncIteration` was swallowed by a bare `pass`,
    so the loop could never reach the "Empty document history" handler that already sat below it.
    A resolver fetching did.jsonl from a host that returns an empty body hung instead of failing.
    """
    resolver = DidResolver(MockHistoryVerifier())
    result = await resolver.resolve(
        "did:webvh:QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH:example.com",
        MockHistoryResolver(""),
    )
    assert result.document is None
    assert result.resolution_metadata["error"] == "notFound"
    assert "missing-log" in result.resolution_metadata["problemDetails"]["type"]


@pytest.mark.parametrize("blank", ["\n", "   \n\n"])
async def test_resolve_history_terminates_on_a_whitespace_log(blank):
    """A log of blank lines is malformed JSON Lines rather than an empty log, so `invalidDid` is
    the right answer. What matters here is only that it is *an* answer: before the fix this input
    reached the same non-terminating branch as a truly empty log."""
    resolver = DidResolver(MockHistoryVerifier())
    result = await resolver.resolve(
        "did:webvh:QmadwVpf5ccxz7bGxaweiHSxFcN1MFG415GUpbN9Cnm1hH:example.com",
        MockHistoryResolver(blank),
    )
    assert result.document is None
    assert result.resolution_metadata["error"]
