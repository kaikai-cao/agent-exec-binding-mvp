
from __future__ import annotations

import base64
import json
import multiprocessing as mp
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agent_exec_binding import (
    AuthorizationError,
    MockFinanceTool,
    canonical_json,
    digest_object,
    public_key_bytes,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _public_key_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _private_key_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _verify_issuer_grant(
    issuer_public_key: bytes,
    grant_data: dict[str, Any],
    call_data: dict[str, Any],
    context_data: dict[str, Any],
) -> dict[str, Any]:
    """Verify the issuer signature and all request bindings before querying."""

    if not isinstance(grant_data, dict):
        raise AuthorizationError("invalid grant structure")

    payload = grant_data.get("payload")
    signature_text = grant_data.get("signature")

    if not isinstance(payload, dict) or not isinstance(signature_text, str):
        raise AuthorizationError("invalid grant structure")

    try:
        signature = _unb64(signature_text)
        Ed25519PublicKey.from_public_bytes(issuer_public_key).verify(
            signature,
            canonical_json(payload),
        )
    except (ValueError, TypeError, InvalidSignature):
        raise AuthorizationError("invalid issuer signature") from None

    now = int(time.time())

    expires_at = payload.get("expires_at")
    issued_at = payload.get("issued_at")

    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise AuthorizationError("invalid grant expiry")

    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        raise AuthorizationError("invalid grant issue time")

    if issued_at > now:
        raise AuthorizationError("grant issued in the future")

    if expires_at <= now:
        raise AuthorizationError("grant expired")

    actual_request_hash = digest_object(call_data)
    actual_context_hash = digest_object(context_data)

    if payload.get("request_hash") != actual_request_hash:
        raise AuthorizationError("proxy request hash mismatch")

    if payload.get("context_hash") != actual_context_hash:
        raise AuthorizationError("proxy context hash mismatch")

    if payload.get("tool_id") != MockFinanceTool.TOOL_ID:
        raise AuthorizationError("proxy tool id mismatch")

    if payload.get("tool_schema_hash") != MockFinanceTool.SCHEMA_HASH:
        raise AuthorizationError("proxy tool schema hash mismatch")

    if call_data.get("tool_id") != MockFinanceTool.TOOL_ID:
        raise AuthorizationError("request tool id mismatch")

    if call_data.get("agent_id") != payload.get("agent_id"):
        raise AuthorizationError("request agent id mismatch")

    if not isinstance(call_data.get("args"), dict):
        raise AuthorizationError("invalid tool arguments")

    return payload


def _execute_owned_query(call_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Execute against data created and owned inside the Proxy process."""

    args = call_data["args"]
    fields = args.get("fields")
    where = args.get("where")
    limit = args.get("limit")

    if (
        not isinstance(fields, list)
        or not fields
        or any(not isinstance(field, str) for field in fields)
    ):
        raise AuthorizationError("invalid query fields")

    if not isinstance(where, dict):
        raise AuthorizationError("invalid query filters")

    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise AuthorizationError("invalid query limit")

    # This dataset is constructed inside the Proxy process. It is not
    # imported from or queried through the Adapter.
    records = [
        {
            "year": 2026,
            "department": "Sales",
            "amount": 1200,
            "id_number": "SENSITIVE-001",
        },
        {
            "year": 2026,
            "department": "Finance",
            "amount": 3400,
            "id_number": "SENSITIVE-002",
        },
        {
            "year": 2025,
            "department": "Sales",
            "amount": 900,
            "id_number": "SENSITIVE-003",
        },
    ]

    matched = [
        record
        for record in records
        if all(record.get(key) == value for key, value in where.items())
    ]

    selected = matched[:limit]

    return [
        {field: record[field] for field in fields if field in record}
        for record in selected
    ]


def _proxy_process_main(
    issuer_public_key: bytes,
    startup_pipe: Any,
    query_counter: Any,
) -> None:
    """Child-process entry point. The Proxy private key and dataset live here."""

    proxy_private_key = Ed25519PrivateKey.generate()
    proxy_public_key = proxy_private_key.public_key()
    consumed_nonces: set[str] = set()
    nonce_lock = threading.Lock()

    class ProxyHandler(BaseHTTPRequestHandler):
        server_version = "IndependentExecutionProxy/1.0"

        def log_message(self, format: str, *args: Any) -> None:
            # Keep test output deterministic and avoid logging request contents.
            return

        def _send_json(self, status: int, body: dict[str, Any]) -> None:
            encoded = canonical_json(body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self) -> None:
            if self.path != "/execute":
                self._send_json(404, {"error": "not found"})
                return

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"error": "invalid content length"})
                return

            if content_length <= 0 or content_length > 1_000_000:
                self._send_json(400, {"error": "invalid request size"})
                return

            try:
                raw_body = self.rfile.read(content_length)
                request_data = json.loads(raw_body.decode("utf-8"))

                if not isinstance(request_data, dict):
                    raise ValueError("request must be an object")

                call_data = request_data["call"]
                context_data = request_data["context"]
                grant_data = request_data["grant"]

                if not isinstance(call_data, dict):
                    raise ValueError("call must be an object")

                if not isinstance(context_data, dict):
                    raise ValueError("context must be an object")

                grant_payload = _verify_issuer_grant(
                    issuer_public_key,
                    grant_data,
                    call_data,
                    context_data,
                )

                nonce = grant_payload.get("nonce")
                if not isinstance(nonce, str) or not nonce:
                    raise AuthorizationError("invalid grant nonce")

                # Consume the nonce atomically before the query begins.
                with nonce_lock:
                    if nonce in consumed_nonces:
                        raise AuthorizationError("grant nonce already consumed")
                    consumed_nonces.add(nonce)

                with query_counter.get_lock():
                    query_counter.value += 1

                output = _execute_owned_query(call_data)

                evidence_payload = {
                    "evidence_version": "iee-proxy-evidence-v1",
                    "execution_id": str(uuid.uuid4()),
                    "grant_hash": digest_object(grant_data),
                    "request_hash": digest_object(call_data),
                    "context_hash": digest_object(context_data),
                    "tool_id": call_data["tool_id"],
                    "tool_schema_hash": MockFinanceTool.SCHEMA_HASH,
                    "nonce": nonce,
                    "query_hash": digest_object(call_data.get("args")),
                    "output_hash": digest_object(output),
                    "row_count": len(output),
                    "source_id": "mock-finance-dataset-v1",
                    "snapshot_id": "mock-finance-snapshot-v1",
                }

                evidence_signature = proxy_private_key.sign(
                    canonical_json(evidence_payload)
                )

                evidence = {
                    "payload": evidence_payload,
                    "signature": _b64(evidence_signature),
                }

                self._send_json(
                    200,
                    {
                        "output": output,
                        "evidence": evidence,
                    },
                )

            except AuthorizationError as exc:
                self._send_json(403, {"error": str(exc)})
            except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid request"})
            except Exception:
                self._send_json(500, {"error": "proxy internal error"})

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        server.daemon_threads = True

        port = server.server_address[1]

        startup_pipe.send(
            {
                "status": "ready",
                "port": port,
                "proxy_public_key": _b64(_public_key_raw(proxy_public_key)),
            }
        )
        startup_pipe.close()

        server.serve_forever(poll_interval=0.1)

    except BaseException as exc:
        try:
            startup_pipe.send(
                {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
        except Exception:
            pass
        raise


class IndependentExecutionProxy:
    """Parent-side lifecycle and trusted observation handle for the Proxy."""

    def __init__(
        self,
        issuer_public_key: bytes | str,
        startup_timeout: float = 10.0,
    ) -> None:
        if isinstance(issuer_public_key, str):
            issuer_public_key = _unb64(issuer_public_key)

        self._ctx = mp.get_context("spawn")
        self._query_counter = self._ctx.Value("i", 0)

        parent_pipe, child_pipe = self._ctx.Pipe(duplex=False)

        self._process = self._ctx.Process(
            target=_proxy_process_main,
            args=(
                issuer_public_key,
                child_pipe,
                self._query_counter,
            ),
            name="independent-execution-proxy",
            daemon=True,
        )

        self._process.start()
        child_pipe.close()

        if not parent_pipe.poll(startup_timeout):
            self._process.terminate()
            self._process.join(timeout=3)
            parent_pipe.close()
            raise RuntimeError("Proxy process startup timed out")

        startup = parent_pipe.recv()
        parent_pipe.close()

        if startup.get("status") != "ready":
            self._process.join(timeout=3)
            raise RuntimeError(
                f"Proxy process startup failed: {startup.get('error', 'unknown error')}"
            )

        self.port = int(startup["port"])
        self.url = f"http://127.0.0.1:{self.port}/execute"
        self.proxy_public_key = _unb64(startup["proxy_public_key"])

    @property
    def query_count(self) -> int:
        """Read the process-shared counter, not an Adapter-supplied metric."""

        with self._query_counter.get_lock():
            return int(self._query_counter.value)

    def close(self) -> None:
        if self._process.is_alive():
            self._process.terminate()
        self._process.join(timeout=3)

    def __enter__(self) -> "IndependentExecutionProxy":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class ProxyAdapter:
    """Adapter-side HTTP client. It does not own the dataset or Proxy key."""

    def __init__(self, proxy: IndependentExecutionProxy) -> None:
        self.proxy = proxy

    def execute(
        self,
        call: Any,
        context: Any,
        grant: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        request_body = {
            "call": call.as_dict(),
            "context": context.as_dict(),
            "grant": grant.as_dict(),
        }

        request = urllib.request.Request(
            self.proxy.url,
            data=canonical_json(request_body),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                try:
                    error_data = json.loads(exc.read().decode("utf-8"))
                    reason = error_data.get("error", "proxy rejected request")
                except Exception:
                    reason = f"proxy returned HTTP {exc.code}"
            finally:
                exc.close()
            raise AuthorizationError(reason) from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError(f"Proxy communication failed: {exc}") from None

        if not isinstance(response_data, dict):
            raise RuntimeError("Proxy returned an invalid response")

        output = response_data.get("output")
        evidence = response_data.get("evidence")

        if not isinstance(output, list) or not isinstance(evidence, dict):
            raise RuntimeError("Proxy response is missing output or evidence")

        return output, evidence


def verify_proxy_evidence(
    proxy_public_key: bytes,
    evidence: dict[str, Any],
    call: Any,
    context: Any,
    grant: Any,
    output: list[dict[str, Any]],
) -> bool:
    """Verify Proxy signature and bind its evidence to the original execution."""

    try:
        if not isinstance(evidence, dict):
            return False

        payload = evidence.get("payload")
        signature_text = evidence.get("signature")

        if not isinstance(payload, dict) or not isinstance(signature_text, str):
            return False

        Ed25519PublicKey.from_public_bytes(proxy_public_key).verify(
            _unb64(signature_text),
            canonical_json(payload),
        )

        call_data = call.as_dict()
        context_data = context.as_dict()
        grant_data = grant.as_dict()
        grant_payload = grant_data["payload"]

        expected = {
            "evidence_version": "iee-proxy-evidence-v1",
            "grant_hash": digest_object(grant_data),
            "request_hash": digest_object(call_data),
            "context_hash": digest_object(context_data),
            "tool_id": call_data["tool_id"],
            "tool_schema_hash": MockFinanceTool.SCHEMA_HASH,
            "nonce": grant_payload["nonce"],
            "query_hash": digest_object(call_data.get("args")),
            "output_hash": digest_object(output),
            "row_count": len(output),
        }

        return all(payload.get(key) == value for key, value in expected.items())

    except (
        InvalidSignature,
        KeyError,
        TypeError,
        ValueError,
        AttributeError,
    ):
        return False


class IndependentEvidenceGateway:
    """Gateway pins the Proxy key and verifies evidence against original inputs."""

    def __init__(
        self,
        adapter: ProxyAdapter,
        pinned_proxy_public_key: bytes,
    ) -> None:
        self.adapter = adapter
        self.pinned_proxy_public_key = bytes(pinned_proxy_public_key)

    def execute(
        self,
        call: Any,
        context: Any,
        grant: Any,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        output, evidence = self.adapter.execute(call, context, grant)

        if not verify_proxy_evidence(
            self.pinned_proxy_public_key,
            evidence,
            call,
            context,
            grant,
            output,
        ):
            raise AuthorizationError("proxy evidence verification failed")

        return output, evidence
