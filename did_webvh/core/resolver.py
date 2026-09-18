"""Support for DID resolution."""

import json
from asyncio import Event, Future, ensure_future, get_running_loop
from collections.abc import Awaitable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from inspect import isawaitable
from pathlib import Path
from typing import Optional

from .date_utils import make_timestamp
from .file_utils import (
    AsyncTextGenerator,
    AsyncTextReadError,
    read_text_file,
)
from .problem_details import ProblemDetails
from .state import (
    DocumentMetadata,
    DocumentState,
    InvalidDocumentState,
    check_version_time,
    verify_state_proofs,
)
from .witness import WitnessChecks, WitnessRule, verify_witness_proofs


class ResolutionError(Exception):
    """An error raised during DID resolution."""

    error: str
    problem_details: ProblemDetails | list[ProblemDetails] | None = None

    def __init__(
        self,
        error: str,
        problem_details: ProblemDetails | list[ProblemDetails] | None = None,
    ):
        """Initializer."""
        super().__init__(error)
        self.error = error
        self.problem_details = problem_details

    @classmethod
    def invalid_did(
        cls, problem_details: ProblemDetails | list[ProblemDetails] | None = None
    ) -> "ResolutionError":
        """Initialize a new `invalidDid` resolution error."""
        return cls("invalidDid", problem_details)

    @classmethod
    def not_found(
        cls, problem_details: ProblemDetails | list[ProblemDetails] | None = None
    ) -> "ResolutionError":
        """Initialize a new `notFound` resolution error."""
        return cls("notFound", problem_details)

    def serialize(self) -> dict:
        """Serialize this error to a JSON-compatible dictionary."""
        details = self.problem_details
        if isinstance(details, list):
            details = [det.serialize() for det in details]
        elif isinstance(details, ProblemDetails):
            details = details.serialize()
        else:
            details = None
        return {
            "contentType": "application/did+ld+json",
            "error": self.error,
            **({"problemDetails": details} if details else {}),
        }


@dataclass
class ResolutionResult:
    """The result of a DID resolution operation."""

    document: Optional[dict] = None
    document_metadata: Optional[dict] = None
    resolution_metadata: Optional[dict] = None

    def __init__(
        self,
        document: Optional[dict] = None,
        document_metadata: Optional[dict] = None,
        resolution_metadata: Optional[dict] = None,
    ):
        """Initializer."""
        super().__init__()
        if isinstance(resolution_metadata, ResolutionError):
            resolution_metadata = resolution_metadata.serialize()
        self.document = document
        self.document_metadata = document_metadata
        self.resolution_metadata = resolution_metadata

    def serialize(self) -> dict:
        """Serialize this result to a JSON-compatible dictionary."""
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "didDocument": self.document,
            "didDocumentMetadata": self.document_metadata,
            "didResolutionMetadata": self.resolution_metadata,
        }


@dataclass
class DereferencingResult:
    """The result of a DID dereferencing operation."""

    dereferencing_metadata: dict
    content: str = ""
    content_metadata: Optional[dict] = None

    def serialize(self) -> dict:
        """Serialize this result to a JSON-compatible dictionary."""
        return {
            "@context": "https://w3id.org/did-resolution/v1",
            "dereferencingMetadata": self.dereferencing_metadata,
            "content": self.content,
            "contentMetadata": self.content_metadata or {},
        }


class HistoryResolver:
    """Generic history resolver base class."""

    def resolve_entry_log(self, document_id: str | None) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        raise NotImplementedError()

    def resolve_witness_log(self, document_id: str | None) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        raise NotImplementedError()


class LocalHistoryResolver(HistoryResolver):
    """A history resolver which loads local log files."""

    def __init__(
        self,
        entry_path: str | Path,
        witness_path: str | Path | None = None,
    ):
        """Constructor."""
        self.entry_path = Path(entry_path)
        self.witness_path = Path(witness_path) if witness_path else None

    def resolve_entry_log(self, _document_id: str | None) -> AsyncTextGenerator:
        """Resolve the entry log file for a DID."""
        return read_text_file(self.entry_path)

    def resolve_witness_log(self, _document_id: str | None) -> AsyncTextGenerator:
        """Resolve the witness log file for a DID."""
        if self.witness_path:
            return read_text_file(self.witness_path)
        raise AsyncTextReadError("Missing witness log path")


class HistoryVerifier:
    """Generic DID verifier class."""

    _resolution_time: datetime | None = None
    _future_skew: timedelta | None = None

    def __init__(
        self,
        verify_proofs: bool = True,
        *,
        enforce_future_skew: bool = True,
        future_skew: timedelta | None = None,
        resolution_time: datetime | None = None,
    ):
        """Constructor.

        Args:
            verify_proofs: Verify Data Integrity proofs on each log entry.
            enforce_future_skew: Reject `versionTime` values in the future,
                as required by did:webvh.
            future_skew: Permitted clock skew for `versionTime` (default 5 minutes).
            resolution_time: The time to check `versionTime` against. Defaults
                to the time the verifier is created, so that every log entry is
                checked against the same time. Use a new verifier for each resolution.

        """
        if future_skew is not None and future_skew < timedelta(0):
            raise ValueError("future_skew must not be negative")
        self._verify_proofs = verify_proofs
        self._enforce_future_skew = enforce_future_skew
        self._resolution_time = resolution_time or datetime.now(timezone.utc)
        self._future_skew = future_skew

    def verify_state(
        self, state: DocumentState, prev_state: DocumentState | None, is_final: bool
    ) -> Awaitable[None] | None:
        """Verify a document state."""
        check_version_time(
            state,
            prev_state,
            enforce_future_skew=self._enforce_future_skew,
            future_skew=self._future_skew,
            resolution_time=self._resolution_time,
        )
        if (
            prev_state
            and prev_state.document_id != state.document_id
            and not prev_state.params.get("portable", False)
        ):
            raise InvalidDocumentState(
                ProblemDetails(
                    type="#portability-disabled",
                    title="Document ID updated on non-portable DID",
                )
            )

        if self._verify_proofs:
            # and state.version_number == 1 or state.is_authz_event or is_final
            return get_running_loop().run_in_executor(
                None, verify_state_proofs, state, prev_state
            )


class VerifyTasks:
    """Collect the results of verification tasks."""

    def __init__(self):
        """Create a new instance."""
        self.failed: dict[int, list] = {}
        self.pending: dict[Future, int] = {}
        self.done = Event()
        self.done.set()

    def add_failure(self, version_number: int, err: Exception):
        """Add a failure to the results."""
        if version_number not in self.failed:
            self.failed[version_number] = []
        self.failed[version_number].append(err)

    def add_task(self, version_number: int, task: Awaitable):
        """Add a verification task to be tracked."""
        self.done.clear()
        task = ensure_future(task)
        self.pending[task] = version_number
        task.add_done_callback(self._handle_callback)

    def __await__(self):
        """Allow awaiting the task collection."""
        return self.done.wait().__await__()

    def _handle_callback(self, future: Future):
        """Handle a task callback."""
        version_number = self.pending.pop(future, None)
        if not version_number:
            raise KeyError("Received callback for unscheduled task")
        exc = future.exception()
        if exc:
            self.add_failure(version_number, exc)
        if not self.pending:
            self.done.set()


class DidResolver:
    """Generic DID resolver class, which accepts a custom log resolver and verifier."""

    def __init__(self, verifier: HistoryVerifier):
        """Constructor."""
        self.verifier = verifier

    async def resolve(
        self,
        document_id: str,
        source: HistoryResolver,
        *,
        version_id: str | None = None,
        version_number: int | str | None = None,
        version_time: datetime | str | None = None,
    ) -> ResolutionResult:
        """Resolve a `ResolutionResult` from a document ID and history resolver.

        Params:
            document_id: the DID to be resolved
            source: the `HistoryResolver` instance to use
            version_id: stop parsing at the requested versionId (may be numeric)
            version_time: stop parsing at the most recent entry before
                or exactly matching the requested versionTime
        """
        try:
            state, doc_meta = await self.resolve_state(
                document_id,
                source,
                version_id=version_id,
                version_number=version_number,
                version_time=version_time,
            )
        except AsyncTextReadError as err:
            return ResolutionResult(
                resolution_metadata=ResolutionError.not_found(
                    ProblemDetails(
                        type="#missing-log",
                        title="Missing log",
                        detail=f"History resolution error: {str(err)}",
                    ),
                )
            )
        except ResolutionError as err:
            return ResolutionResult(resolution_metadata=err)

        if state.document_id != document_id:
            res_result = ResolutionResult(
                resolution_metadata=ResolutionError.invalid_did(
                    ProblemDetails(
                        type="#did-log-id-mismatch",
                        title="Document ID mismatch",
                        detail=(
                            "A DID Log File was found, but the id in the DID Document"
                            " does not match the DID being resolved."
                        ),
                        found=state.document_id,
                        expected=document_id,
                    ),
                )
            )
        else:
            res_result = ResolutionResult(
                document=state.document, document_metadata=doc_meta.serialize()
            )
        return res_result

    async def resolve_state(
        self,
        document_id: str | None,
        source: HistoryResolver,
        *,
        version_id: str | None = None,
        version_number: int | str | None = None,
        version_time: str | datetime | None = None,
        verify_witness: bool = True,
    ) -> tuple[DocumentState, DocumentMetadata]:
        """Resolve a specific document state and document metadata."""
        aborted_err: ResolutionError | None = None
        created: datetime | None = None
        exhausted: bool = False
        found: DocumentState | None = None
        prev_state: DocumentState | None = None
        state: DocumentState | None = None
        next_state: DocumentState | None = None
        line_no: int = 0
        version_ids: list[str] = []
        verify_tasks = VerifyTasks()
        witness_checks: dict[WitnessRule, int] = {}
        witness_load_task: Future | None = None

        if isinstance(version_time, str):
            try:
                version_time = make_timestamp(version_time)[0]
            except ValueError:
                raise ResolutionError.not_found(
                    ProblemDetails.invalid_resolution_parameter("Invalid `versionTime`"),
                ) from None

        if isinstance(version_number, str):
            if not version_number:
                version_number = None
            else:
                try:
                    version_number = int(version_number)
                except ValueError:
                    version_number = None
                if not version_number:
                    raise ResolutionError.not_found(
                        ProblemDetails.invalid_resolution_parameter(
                            "Invalid `versionNumber`"
                        ),
                    )
        else:
            version_number = None

        if isinstance(version_id, str):
            if not version_id:
                version_id = None
            else:
                try:
                    vnum = int(version_id.split("-", 1)[0])
                except ValueError:
                    vnum = None
                if not vnum:
                    raise ResolutionError.not_found(
                        ProblemDetails.invalid_resolution_parameter(
                            "Invalid `versionId`"
                        ),
                    ) from None
                if not version_number:
                    version_number = vnum

        async with source.resolve_entry_log(document_id) as entry_log:
            while not aborted_err and not verify_tasks.failed:
                prev_state = state
                state = next_state
                next_state = None

                try:
                    line_no += 1
                    line = await anext(entry_log)
                    next_state = DocumentState.load_history_json(line, state)
                    next_state.check_version_id()
                except StopAsyncIteration:
                    exhausted = True
                except InvalidDocumentState as err:
                    aborted_err = ResolutionError.invalid_did(err.problem_details)
                    next_state = None

                if not state:
                    if exhausted:
                        # The log held no entries at all, so the two-line lookahead below never
                        # primes and `state` can never become set. Without this the loop spins
                        # forever; breaking here reaches the "Empty document history" handler
                        # after the loop, which is what this case was always meant to report.
                        break
                    # we initially loop twice so that the next line is available (if any)
                    continue

                if not found:
                    if version_number:
                        if state.version_number == version_number:
                            if version_time and state.timestamp > version_time:
                                raise ResolutionError.not_found(
                                    ProblemDetails.invalid_resolution_parameter(
                                        "Specified `versionId` not valid at `versionTime`"
                                    ),
                                )
                            if version_id is not None and state.version_id != version_id:
                                raise ResolutionError.not_found(
                                    ProblemDetails.invalid_resolution_parameter(
                                        "`versionId` mismatch with `versionNumber`"
                                    ),
                                )
                            found = state
                    elif version_time and (
                        (next_state and next_state.timestamp > version_time)
                        or (not next_state and not aborted_err)
                    ):
                        if state.timestamp > version_time:
                            raise ResolutionError.not_found(
                                ProblemDetails.invalid_resolution_parameter(
                                    "Resolved version not valid at `versionTime`"
                                ),
                            )
                        found = state

                try:
                    verify = self.verifier.verify_state(state, prev_state, not next_state)
                except InvalidDocumentState as err:
                    verify_tasks.add_failure(state.version_number, err)
                else:
                    if isawaitable(verify):
                        verify_tasks.add_task(state.version_number, verify)
                version_ids.append(state.version_id)
                if (
                    verify_witness
                    and (witness_rule := (prev_state or state).witness_rule)
                    and witness_rule.threshold != 0
                ):
                    witness_checks[witness_rule] = state.version_number
                    if not witness_load_task:
                        witness_load_task = ensure_future(
                            self.load_witness_log(document_id, source),
                        )

                if not created:
                    created = state.timestamp
                if not next_state:
                    break

        if not found:
            if aborted_err:
                raise aborted_err
            if not state:
                raise ResolutionError.not_found(
                    ProblemDetails(
                        type="#missing-log",
                        title="Missing log",
                        detail="Empty document history",
                    ),
                )
            if version_id or version_number or version_time:
                # FIXME may adjust problem details based on request parameters
                raise ResolutionError.not_found()
            found = state

        # collect all verification results
        await verify_tasks
        if verify_tasks.failed:
            failed_numbers = list(verify_tasks.failed.keys())
            failed_numbers.sort()
            failed_ver = failed_numbers.pop(0)
            failed_errs = verify_tasks.failed[failed_ver]
            if failed_ver <= found.version_number:
                raise ResolutionError.invalid_did(failed_errs[0].problem_details)
            else:
                # FIXME add failed version info to resolution metadata
                # adjust 'updated'?
                pass

        # check witness proofs
        if witness_load_task:
            validated, _errs = await witness_load_task
            checks = WitnessChecks(rules=witness_checks, versions=version_ids)
            valid = checks.verify(validated)
            if not valid and found.version_number < state.version_number:
                # FIXME add failed check to resolution metadata
                valid = checks.verify(validated, at_version=found.version_number)
            if not valid:
                raise ResolutionError.invalid_did(
                    ProblemDetails(
                        type="#witness-verification-failed",
                        title="Insufficient witness proofs.",
                    ),
                )

        doc_meta = DocumentMetadata(
            created=created,
            updated=state.timestamp,
            deactivated=found.deactivated,
            portable=found.portable,
            scid=found.scid,
            ttl=str(found.ttl),
            version_id=found.version_id,
            version_time=found.timestamp,
            watchers=found.watchers,
            witness=found.witness,
        )
        return found, doc_meta

    async def load_witness_log(
        self,
        document_id: str | None,
        source: HistoryResolver,
    ) -> tuple[dict, list]:
        """Retrieve and verify the witness log."""
        async with source.resolve_witness_log(document_id) as witness_log:
            witness_text = await witness_log.text()
        try:
            proofs = json.loads(witness_text)
        except ValueError as e:
            raise ValueError(f"Invalid witness JSON: {e}") from None
        if not isinstance(proofs, list):
            raise ValueError("Invalid witness JSON: expected list")
        return await verify_witness_proofs(proofs)


def _add_ref(doc_id: str, node: dict, refmap: dict, all: set):
    reft = node.get("id")
    if not isinstance(reft, str):
        return
    if reft.startswith("#"):
        reft = doc_id + reft
    elif "#" not in reft:
        return
    if reft in all:
        raise ValueError(f"Duplicate reference: {reft}")
    all.add(reft)
    refmap[reft] = node


def reference_map(document: dict) -> dict[str, dict]:
    """Collect identified fragments (#ids) in a DID Document."""
    # indexing top-level collections only
    doc_id = document.get("id")
    if not isinstance(doc_id, str):
        raise ValueError("Missing document id")
    all = set()
    res = {}
    for k, v in document.items():
        if k == "@context":
            continue
        if isinstance(v, dict):
            res[k] = {}
            _add_ref(doc_id, v, res[k], all)
        elif isinstance(v, list):
            res[k] = {}
            for vi in v:
                if isinstance(vi, dict):
                    _add_ref(doc_id, vi, res[k], all)
    return res


def normalize_services(document: dict) -> list[dict]:
    """Normalize a `service` block to a list of dicts."""
    svcs = document.get("service", [])
    if not isinstance(svcs, list):
        svcs = [svcs]
    for svc in svcs:
        if not isinstance(svc, dict):
            raise ValueError("Expected map or list of map entries for 'service' property")
        svc_id = svc.get("id")
        if not svc_id or not isinstance(svc_id, str) or "#" not in svc_id:
            raise ValueError(f"Invalid service entry id: {svc_id}")
    return svcs


def dereference_fragment(document: dict, reft: str) -> DereferencingResult:
    """Dereference a fragment identifier within a document."""
    res = None
    try:
        if not reft.startswith("#"):
            raise ValueError("Expected reference to begin with '#'")
        refts = reference_map(document)
        reft = document["id"] + reft
        for blk in refts.values():
            if reft in blk:
                res = deepcopy(blk[reft])
                break
    except ValueError:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError.not_found(
                # str(err)
            ).serialize(),
        )
    if not res:
        return DereferencingResult(
            dereferencing_metadata=ResolutionError.not_found(
                # f"Reference not found: {reft}"
            ).serialize()
        )
    ctx = []
    doc_ctx = document.get("@context")
    if isinstance(doc_ctx, str):
        ctx.append(doc_ctx)
    elif isinstance(doc_ctx, list):
        ctx.extend(doc_ctx)
    node_ctx = res.get("@context")
    if isinstance(node_ctx, str):
        ctx.append(node_ctx)
    elif isinstance(node_ctx, list):
        ctx.extend(node_ctx)
    if ctx:
        res = {"@context": ctx, **res}
    return DereferencingResult(dereferencing_metadata={}, content=json.dumps(res))
