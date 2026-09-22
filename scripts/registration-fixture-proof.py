#!/usr/bin/env python3
"""Prepare and verify the shutdown registration-fixture negative control."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


AUTHORITATIVE_CHECK = """            if shutting_down.load(Ordering::Relaxed) {
                drop(lifecycle);
                return refuse_registration(&peer_id, connection);
            }
"""
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SUMMARY = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mutate(source: Path, receipt: Path) -> None:
    original = source.read_bytes()
    text = original.decode("utf-8")
    count = text.count(AUTHORITATIVE_CHECK)
    if count != 1:
        raise SystemExit(f"expected one authoritative check, found {count}")
    mutated = text.replace(AUTHORITATIVE_CHECK, "", 1).encode()
    source.write_bytes(mutated)
    receipt.write_text(
        json.dumps(
            {
                "removed_authoritative_checks": count,
                "source": str(source),
                "source_sha256_before": sha256(original),
                "source_sha256_after": sha256(mutated),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def summaries(log: Path) -> tuple[str, list[tuple[str, str, str]]]:
    text = ANSI.sub("", log.read_text(encoding="utf-8", errors="replace"))
    return text, SUMMARY.findall(text)


def verify(log: Path, mode: str) -> None:
    text, rows = summaries(log)
    expected = [("1", "0", "0")] if mode == "positive" else [("0", "1", "0")]
    if rows != expected:
        raise SystemExit(f"unexpected {mode} summaries: {rows!r}")
    if mode == "negative":
        required = (
            "a post-sweep registrar must be refused and drop its task-local connection",
            "LiveInserted",
            "RefusedAndDropped",
        )
        missing = [token for token in required if token not in text]
        if missing:
            raise SystemExit(f"negative log lacks assertion evidence: {missing!r}")
        forbidden = ("error: could not compile", "shutdown did not pause", "did not finish")
        found = [token for token in forbidden if token in text]
        if found:
            raise SystemExit(f"negative failed outside the intended oracle: {found!r}")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    mutation = sub.add_parser("mutate")
    mutation.add_argument("source", type=Path)
    mutation.add_argument("receipt", type=Path)
    verification = sub.add_parser("verify")
    verification.add_argument("mode", choices=("positive", "negative"))
    verification.add_argument("log", type=Path)
    args = parser.parse_args()
    if args.command == "mutate":
        mutate(args.source, args.receipt)
    else:
        verify(args.log, args.mode)


if __name__ == "__main__":
    main()
