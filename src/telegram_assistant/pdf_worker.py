"""Memory-bounded local PDF text extraction child process."""
from __future__ import annotations

import json
import sys
from pathlib import Path

PDF_WORKER_MEMORY_BYTES = 256 * 1024 * 1024

def main() -> int:
    try:
        import resource
    except Exception:
        print(json.dumps({"error": "document_isolation_unavailable"}))
        return 0
    try:
        cpu_limit = 30
        cpu_hard_limit = resource.getrlimit(resource.RLIMIT_CPU)[1]
        if cpu_hard_limit != resource.RLIM_INFINITY:
            cpu_limit = min(cpu_limit, cpu_hard_limit)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit))
    except Exception:
        print(json.dumps({"error": "document_isolation_unavailable"}))
        return 0
    try:
        memory_limit = PDF_WORKER_MEMORY_BYTES
        memory_hard_limit = resource.getrlimit(resource.RLIMIT_AS)[1]
        if memory_hard_limit != resource.RLIM_INFINITY:
            memory_limit = min(memory_limit, memory_hard_limit)
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
    except Exception:
        # On macOS the interpreter may already have address-space mappings above
        # this cap; the child and CPU/wall-clock limits still bound parser work.
        if sys.platform != "darwin":
            print(json.dumps({"error": "document_isolation_unavailable"}))
            return 0

    try:
        from .media import extract_document_text
        if len(sys.argv) != 2:
            raise ValueError
        result = extract_document_text(Path(sys.argv[1]))
        payload = {"text": result.text, "pages": result.pages,
                   "truncated": result.truncated}
    except Exception as exc:
        from .security import Denied
        code = exc.code if isinstance(exc, Denied) else "document_parse_failed"
        payload = {"error": code}
    print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
