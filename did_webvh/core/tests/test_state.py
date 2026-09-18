import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from json import JSONDecodeError

import pytest

from did_webvh.askar import AskarSigningKey
from did_webvh.core.hash_utils import HashInfo
from did_webvh.core.state import (
    MAX_TTL,
    DocumentMetadata,
    DocumentState,
    InvalidDocumentState,
    check_version_time,
    verify_state_proofs,
)


@pytest.fixture()
def mock_sk() -> AskarSigningKey:
    return AskarSigningKey.from_jwk(
        '{"crv":"Ed25519","kty":"OKP","x":"iWIGdqmPSeg8Ov89VzUrKuLD7pJ8_askEwJGE1R5Zqk","d":"RJDq2-dY85mW1bbDMcrXPObeL-Ud-b8MrPO-iqxajv0"}'
    )


@pytest.fixture()
def mock_next_sk() -> AskarSigningKey:
    return AskarSigningKey.from_jwk(
        '{"crv":"Ed25519","kty":"OKP","x":"xeHpv1RMsUQUYQ74BFTcVTifqFjbkn-pjK9InsVt8EU","d":"uHFsgrJ9xQ8npyB5pNwjPdn7xABkGKYmXD2ZV5spz6I"}'
    )


@pytest.fixture()
def mock_document() -> dict:
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://identity.foundation/.well-known/did-configuration/v1",
            "https://identity.foundation/linked-vp/contexts/v1",
        ],
        "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
        "authentication": [
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
        ],
        "service": [
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#domain",
                "type": "LinkedDomains",
                "serviceEndpoint": "https://example.com%3A5000",
            },
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#whois",
                "type": "LinkedVerifiablePresentation",
                "serviceEndpoint": "https://example.com%3A5000/whois.vp",
            },
        ],
        "verificationMethod": [
            {
                "id": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
                "controller": "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000",
                "type": "Multikey",
                "publicKeyMultibase": "z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs",
            }
        ],
        "assertionMethod": [
            "did:tdw:QmWtQu5Vwi5n7oTz1NHKPtRJuBQmNneLXBGkQW9YBaGYk4:example.com%3A5000#z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
        ],
    }


@pytest.fixture()
def mock_document_state(mock_sk, mock_next_sk) -> DocumentState:
    pk1 = mock_sk.multikey
    pk2 = mock_next_sk.multikey
    next_pk = HashInfo.from_name("sha2-256").formatted_hash(pk2.encode("utf-8"))
    return DocumentState(
        params={
            "updateKeys": [pk1],
            "nextKeyHashes": [next_pk],
            "method": "did:tdw:0.4",
            "scid": "QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        },
        params_update={
            "updateKeys": [pk1],
            "nextKeyHashes": [next_pk],
            "method": "did:tdw:0.4",
            "scid": "QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3:domain.example",
        },
        timestamp=datetime(2024, 9, 17, 17, 29, 32, 0, tzinfo=timezone.utc),
        timestamp_raw="2024-09-11T17:29:32Z",
        version_id="1-QmXXb2mW7hZVLM5PPjm5iKCYS2PHQnoLePLK1d172ABrDZ",
        version_number=1,
        last_version_id="QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        proofs=[
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
                "created": "2024-12-11T21:49:26Z",
                "proofPurpose": "authentication",
                "proofValue": "z3bAmyurHc7S5junyQ3s92HSMVn1bQUqLfmaoMCuyArDM9TtFaPEPB69bBApxXFZcg6nWnZCb2EtKrg24trXbqh2A",
            }
        ],
    )


def test_initial_document_state():
    # Valid
    DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document='{"@context": ["https://www.w3.org/ns/did/v1"],"id": "did:webvh:{SCID}:domain.example"}',
    )

    # Invalid json document string
    with pytest.raises(JSONDecodeError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:webvh:0.4",
            },
            document='{"@context": ["https://www.w3.org/ns/did/v1"],"id": "did:webvh:{SCID}:domain.example",}',
        )
    # Doc id is not a string
    with pytest.raises(ValueError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:webvh:0.4",
            },
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": 10000,
            },
        )
    # No SCID placeholder
    with pytest.raises(ValueError):
        DocumentState.initial(
            params={
                "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
                "method": "did:webvh:0.4",
            },
            document={
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:{NOTSCID}:domain.example\n",
            },
        )


def test_generate_entry_hash():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )

    generated_hash = doc_state._generate_entry_hash()
    assert isinstance(generated_hash, str)

    hash_info = HashInfo.from_name("sha2-256")
    generated_hash = doc_state._generate_entry_hash(hash_info=hash_info)
    assert isinstance(generated_hash, str)


def test_check_version_id():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    doc_state.check_version_id()

    # Wrong version id
    doc_state.version_id = "1-QmacBLStXRknM45JGFGUnpcBUibBCvNYJEjyUeZcATVC34"
    with pytest.raises(ValueError):
        doc_state.check_version_id()


def test_generate_next_key_hash():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    doc_state.generate_next_key_hash(
        multikey="z6MktKzAfqQr4EurmuyBaB3xq1PJFYe7nrgw6FXWRDkquSAs"
    )


def test_check_scid_derivation():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    doc_state._check_scid_derivation()

    # version id must equal scid
    last_version_id = doc_state.last_version_id
    doc_state.last_version_id = "2-QmUuhGnfMoW8P5JCMWUJi4Ns3WkHsStj2ZEhzpMU7PV8QK"
    with pytest.raises(ValueError):
        doc_state._check_scid_derivation()
    doc_state.last_version_id = last_version_id
    doc_state._check_scid_derivation()

    # Wrong timestamp
    timestamp_raw = doc_state.timestamp_raw
    doc_state.timestamp_raw = "2023-09-10T18:15:05Z"
    with pytest.raises(ValueError):
        doc_state._check_scid_derivation()
    doc_state.timestamp_raw = timestamp_raw
    doc_state._check_scid_derivation()


def test_create_next():
    doc_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            "method": "did:webvh:0.4",
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example\n",
        },
    )
    assert isinstance(doc_state.create_next(), DocumentState)


def test_load_history_line():
    valid_line = {
        "versionId": "1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
        "versionTime": "2024-09-10T18:29:27Z",
        "parameters": {
            "updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],
            "nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],
            "method": "did:webvh:0.5",
            "scid": "QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me",
        },
        "state": {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me:domain.example",
        },
        "proof": [
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                "created": "2024-09-10T18:29:27Z",
                "proofPurpose": "authentication",
                "proofValue": "z4ykWbMWsaLz5QtazW6i6v7ax1T99mvkbMKKf33rPbummsuEnZoDa1puQbTfAiVxe6NdWAyjytyMnmi3gQbJAaCvW",
            }
        ],
    }

    DocumentState.load_history_line(
        valid_line,
        {},
    )

    # Invalid list length - no proof
    line = deepcopy(valid_line)
    del line["proof"]
    with pytest.raises(ValueError):
        DocumentState.load_history_line(
            line,
            {},
        )

    # Invalid - Params isn't a dict
    line = deepcopy(valid_line)
    line["parameters"] = (
        '{"updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],"nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],"method": "did:webvh:0.5","scid": "QmXwpXEc44Rw8A7u7okUvsg3HC69JAKV6b3wX4thyV7nYe",}'
    )
    with pytest.raises(ValueError):
        DocumentState.load_history_line(
            line,
            {},
        )


def test_load_history_line_with_prev_state():
    prev_state = DocumentState.load_history_line(
        {
            "versionId": "1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
            "versionTime": "2024-09-10T18:29:27Z",
            "parameters": {
                "updateKeys": ["z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"],
                "nextKeyHashes": ["QmTnBEPaARViW8ikCA875H8TR21biFPg9rqijdyZG5tzLw"],
                "method": "did:webvh:0.5",
                "scid": "QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me",
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me:domain.example",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                    "created": "2024-09-10T18:29:27Z",
                    "proofPurpose": "authentication",
                    "proofValue": "z4ykWbMWsaLz5QtazW6i6v7ax1T99mvkbMKKf33rPbummsuEnZoDa1puQbTfAiVxe6NdWAyjytyMnmi3gQbJAaCvW",
                }
            ],
        },
        {},
    )

    DocumentState.load_history_line(
        {
            "versionId": "2-QmVRDqG6kCetD54LEcSomsDm7uCpsHbQkdqk7V5J58aV33",
            "versionTime": "2024-09-10T18:29:28Z",
            "parameters": {
                "updateKeys": ["z6MkoSd9jDGV2hyJCb9GiskBPBTY3o4eNs3K9Vr8tCD5Lpkh"],
                "nextKeyHashes": ["QmdkSM2aqyk5Vfcqz4Bw6AKhp3WoFBSL85ydEqAan8UX8A"],
            },
            "state": {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": "did:webvh:QmNTwtP59iQwTK1JjFi3M4zuKkUQUcDspENXEJmSL8zUR9:domain.example",
            },
            "proof": [
                {
                    "type": "DataIntegrityProof",
                    "cryptosuite": "eddsa-jcs-2022",
                    "verificationMethod": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3#z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3",
                    "created": "2024-09-10T18:29:28Z",
                    "proofPurpose": "authentication",
                    "proofValue": "z3vmBNQrQME3R9Y1KgZZbmgpSwT4rwVUBVDwkfmzULADGRxosk2GqvVmGLVRmW8j2SV7zHN1UA97uc2pMM5x7X27N",
                }
            ],
        },
        prev_state=prev_state,
    )


def test_jcs_sign_verify(mock_sk):
    mock_state = DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:{SCID}:domain.example\n",
        },
    )
    method = {
        "type": "Multikey",
        "publicKeyMultibase": mock_sk.multikey,
    }
    proof = mock_state.create_proof(mock_sk)
    mock_state.verify_proof(proof, method)
    proof = mock_state.create_proof(
        sk=mock_sk,
        timestamp=datetime.now(),
    )
    mock_state.verify_proof(proof, method)
    proof = mock_state.create_proof(
        sk=mock_sk,
        timestamp=datetime.now(),
        kid="kid",
    )
    mock_state.verify_proof(proof, method)

    proof["proofPurpose"] = "bad proof"
    with pytest.raises(ValueError):
        mock_state.verify_proof(proof, method)


def test_verify_state_proofs(mock_document_state, mock_next_sk):
    verify_state_proofs(mock_document_state, None)

    pk2 = mock_next_sk.multikey
    prev_state = mock_document_state
    current_state = DocumentState(
        params={
            "updateKeys": [pk2],
            "nextKeyHashes": [],
            "method": "did:webvh:0.5",
            "scid": "QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3",
        },
        params_update={
            "updateKeys": [pk2],
            "nextKeyHashes": [],
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:tdw:QmapF3WxwoFFugMjrnx2iCwfTWuFwxHEBouPmX9fm9jEN3:domain.example",
        },
        timestamp=datetime(2024, 9, 11, 17, 29, 33, 0, tzinfo=timezone.utc),
        timestamp_raw="2024-09-11T17:29:33Z",
        version_id="2-QmdmMJ9BevLMnj6ua7CurAN4wa3RDRrCTgzLWGZPyfpfTV",
        version_number=2,
        last_version_id="1-QmXXb2mW7hZVLM5PPjm5iKCYS2PHQnoLePLK1d172ABrDZ",
        proofs=[
            {
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MksmiAGYB2k2DWnRBeK5qooVKhaRZGXi89PFpKLPboJyor#z6MksmiAGYB2k2DWnRBeK5qooVKhaRZGXi89PFpKLPboJyor",
                "created": "2024-12-11T21:51:46Z",
                "proofPurpose": "authentication",
                "proofValue": "z3XmLPS6ZQ8P7fHydwJN7rR1HG2pvFL5Lb3QA2i4fLUN9gGZkHTcGXXL6oa1GNiLbT5u64murxhhCXB96dhZTPz9a",
            }
        ],
    )

    verify_state_proofs(state=current_state, prev_state=prev_state)

    # Bad proof for current state
    current_state.proofs = [
        {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "did:key:z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun#z6MkohYbQoXp3yHTcwnceL5uuSDukZu2NcP6uAAHANS6dJun",
            "created": "2024-09-11T17:29:33Z",
            "proofPurpose": "authentication",
            "proofValue": "zbsr8px8V9vLvGMeM9znFJqoRmYeRNLAdn5wJ26XmnBMzSS5bb6Us2JG8TKjtooy3ofdRwaWvY4jb6TCVSyhzapZ",  # this is changed
        }
    ]
    with pytest.raises(ValueError):
        verify_state_proofs(state=current_state, prev_state=prev_state)


def test_empty_next_key_hashes_is_equivalent_to_missing():
    """nextKeyHashes: [] from the TS reference generator must resolve without error.

    The TypeScript reference implementation currently serialises nextKeyHashes: []
    when no pre-rotation keys are specified. Per the spec, an empty array is
    semantically equivalent to the field being absent — both mean no pre-rotation
    commitment is made. This behaviour is acceptable and handled here, but the TS
    generator is expected to stop emitting the field entirely in a future release.
    This test should remain in case others decide to use this behaviour.

    The log below is a real TS-generated two-entry DID log; both entries carry
    nextKeyHashes: [] (as well as watchers: [] and witness: {}, also emitted
    by the TS generator for absent optional fields).
    """
    # fmt: off
    log_entries = [
        {
            "versionId": "1-QmPFhMuZH9gjY2JZgyyrgRuFTywQ4mDhoKGVoGE8uy7hFD",
            "versionTime": "2000-01-01T00:00:00Z",
            "parameters": {
                "method": "did:webvh:1.0",
                "scid": "Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg",
                "updateKeys": ["z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"],
                "portable": False,
                "nextKeyHashes": [],
                "watchers": [],
                "witness": {},
                "deactivated": False,
            },
            "state": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1",
                ],
                "id": "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com",
                "controller": "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com",
                "verificationMethod": [{
                    "type": "Multikey",
                    "publicKeyMultibase": "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
                    "purpose": "authentication",
                    "id": "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com#P5RDjVJG",
                }],
                "authentication": ["did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com#P5RDjVJG"],
                "assertionMethod": [],
                "keyAgreement": [],
                "capabilityDelegation": [],
                "capabilityInvocation": [],
            },
            "proof": [{
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
                "created": "2000-01-01T00:00:00Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "z3gfipj528cwTsP7aSSWMsPzA5uqSUGSN7WNzJQFf1WTvjpHf9Ftjk6StQmqqzjyjQT9xyqTjEsRp2jw4DBjcyqac",
            }],
        },
        {
            "versionId": "2-QmXbbxspnFjjt5FX9QEdn8C6D8FZJsFceQdoHFTx89fyT4",
            "versionTime": "2000-01-02T00:00:00Z",
            "parameters": {
                "updateKeys": ["z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"],
                "nextKeyHashes": [],
                "witness": {},
                "watchers": [],
            },
            "state": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1",
                ],
                "id": "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com",
                "controller": "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com",
                "verificationMethod": [{
                    "type": "Multikey",
                    "publicKeyMultibase": "z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
                    "purpose": "authentication",
                    "id": "did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com#P5RDjVJG",
                }],
                "authentication": ["did:webvh:Qmdxt11AjZewCNXX69bpEDobgjySeZ7eFwjf4tgpF6p2Dg:example.com#P5RDjVJG"],
                "assertionMethod": [],
                "keyAgreement": [],
                "capabilityDelegation": [],
                "capabilityInvocation": [],
                "alsoKnownAs": ["did:web:example.com"],
            },
            "proof": [{
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG#z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG",
                "created": "2000-01-02T00:00:00Z",
                "proofPurpose": "assertionMethod",
                "proofValue": "z53PwdwPmSpQoRkumzCVS2buqmTA6GoqaeEyQXJmDPG6diKnctCpcepx8e9NEEobynmM51HMg33kMYPPPWX21rPoy",
            }],
        },
    ]
    # fmt: on

    prev_state = None
    for entry in log_entries:
        state = DocumentState.load_history_json(json.dumps(entry), prev_state)
        assert state.next_key_hashes is None
        verify_state_proofs(state=state, prev_state=prev_state)
        prev_state = state

    assert prev_state.version_number == 2


def test_check_version_time_enforce_future_skew_optional(mock_document_state):
    fixed_now = datetime(2024, 9, 11, 17, 29, 32, tzinfo=timezone.utc)
    future = fixed_now + timedelta(hours=1)
    state = mock_document_state
    state.timestamp = future
    state.timestamp_raw = "2024-09-11T18:29:32Z"

    check_version_time(
        state, None, enforce_future_skew=False, resolution_time=fixed_now
    )

    with pytest.raises(InvalidDocumentState, match="5 minutes in the future"):
        check_version_time(
            state, None, enforce_future_skew=True, resolution_time=fixed_now
        )

    # enforced by default
    with pytest.raises(InvalidDocumentState, match="5 minutes in the future"):
        check_version_time(state, None, resolution_time=fixed_now)


def test_verify_state_proofs_reports_a_mismatched_did_key():
    """A did:key whose body and fragment name different keys is a verification failure.

    `resolve_did_key` raises ValueError for a missing, relative, non-did:key or mismatched
    verification method, and it was called outside the try that catches ValueError -- so the
    exception escaped `verify_state_proofs` uncaught and callers reading `.problem_details` on it
    saw AttributeError rather than a rejection they could report.
    """
    sk = AskarSigningKey.generate("ed25519")
    other = AskarSigningKey.generate("ed25519")
    state = DocumentState.initial(
        {"updateKeys": [sk.multikey], "method": "did:webvh:1.0"},
        {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:example.com",
        },
    )
    state.sign(sk)
    # Body names the authorized key; fragment names a different one.
    state.proofs[0]["verificationMethod"] = f"did:key:{sk.multikey}#{other.multikey}"

    with pytest.raises(InvalidDocumentState) as raised:
        verify_state_proofs(state, None)
    assert raised.value.problem_details.type.endswith("#proof-verification-failed")


def _document_metadata(**kwargs) -> DocumentMetadata:
    timestamp = datetime(2024, 9, 10, 18, 29, 27, tzinfo=timezone.utc)
    return DocumentMetadata(
        created=timestamp,
        updated=timestamp,
        scid="QmQcJ3rAQSyVCjA2P36RUcwf5bQ4ZAB5m9aieqKwWJb7me",
        version_id="1-QmX9fVx3xDJVRY15c2zMvjQN7nKPp4hQsazbbDSGxMwRHG",
        version_time=timestamp,
        **kwargs,
    )


def test_metadata_witness_threshold_is_a_string():
    witness = {
        "threshold": 2,
        "witnesses": [
            {"id": "did:key:z6Mkw1WDm8pd7vwdCBFPrX3VQHMeYcX2nnd9MNiwuHxaZPZ3"}
        ],
    }
    serialized = _document_metadata(witness=witness).serialize()
    assert serialized["witness"]["threshold"] == "2"
    assert serialized["witness"]["witnesses"] == witness["witnesses"]
    # the source rule is left untouched
    assert witness["threshold"] == 2


def test_metadata_reports_empty_watchers_and_witness():
    serialized = _document_metadata().serialize()
    assert serialized["watchers"] == []
    assert serialized["witness"] == {}


def test_metadata_keeps_configured_watchers():
    serialized = _document_metadata(watchers=["https://watcher.example"]).serialize()
    assert serialized["watchers"] == ["https://watcher.example"]


def _ttl_state(params: dict) -> DocumentState:
    """Build a genesis state directly, bypassing SCID derivation over the params."""
    return DocumentState.initial(
        params={
            "updateKeys": ["z6MkrPW2qVDWmgrGn7j7G6SRKSzzkLuujC8oV9wMUzSPQoL4"],
            **params,
        },
        document={
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:{SCID}:domain.example",
        },
    )


@pytest.mark.parametrize(
    "params,expected",
    [
        ({}, 3600),  # not set in the first log entry
        ({"ttl": None}, 3600),  # deprecated, accepted as a request for the default
        ({"ttl": 0}, 0),  # the DID should not be cached
        ({"ttl": 60}, 60),
        ({"ttl": MAX_TTL - 1}, MAX_TTL - 1),
    ],
)
def test_ttl_parameter(params: dict, expected: int):
    assert _ttl_state(params).ttl == expected


@pytest.mark.parametrize("ttl", [None, 0, 60, MAX_TTL - 1])
def test_valid_ttl_parameter_accepted_on_load(ttl):
    assert DocumentState._update_params({}, {"ttl": ttl}) == {"ttl": ttl}


@pytest.mark.parametrize("ttl", [-1, MAX_TTL, True, False, "3600", 1.5, []])
def test_invalid_ttl_parameter_rejected_on_load(ttl):
    with pytest.raises(InvalidDocumentState):
        DocumentState._update_params({}, {"ttl": ttl})
