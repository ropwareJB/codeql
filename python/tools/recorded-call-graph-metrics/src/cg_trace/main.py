import logging
import os
import sys
import time
from datetime import datetime
from io import StringIO

from cg_trace import __version__, cmdline, tracer
from cg_trace.exporter import XMLExporter


def record_calls(code, globals):
    real_stdout = sys.stdout
    real_stderr = sys.stderr
    captured_stdout = StringIO()
    captured_stderr = StringIO()

    sys.stdout = captured_stdout
    sys.stderr = captured_stderr

    cgt = tracer.CallGraphTracer()
    exit_status = cgt.run(code, globals, globals)
    sys.stdout = real_stdout
    sys.stderr = real_stderr

    return sorted(cgt.recorded_calls), captured_stdout, captured_stderr, exit_status


def main(args=None) -> int:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)

    from . import bytecode_reconstructor

    logging.getLogger(bytecode_reconstructor.__name__).setLevel(logging.INFO)

    if args is None:
        # first element in argv is program name
        args = sys.argv[1:]

    opts = cmdline.parse(args)

    # These details of setting up the program to be run is very much inspired by `trace`
    # from the standard library
    sys.argv = [opts.progname, *opts.arguments]
    sys.path[0] = os.path.dirname(opts.progname)

    with open(opts.progname) as fp:
        code = compile(fp.read(), opts.progname, "exec")

    # try to emulate __main__ namespace as much as possible
    globs = {
        "__file__": opts.progname,
        "__name__": "__main__",
        "__package__": None,
        "__cached__": None,
    }

    start = time.time()
    recorded_calls, captured_stdout, captured_stderr, exit_status = record_calls(
        code, globs
    )
    end = time.time()
    elapsed_formatted = f"{end-start:.2f} seconds"

    if opts.xml:
        XMLExporter.export(
            opts.xml,
            recorded_calls,
            info={
                "cg_trace_version": __version__,
                "args": " ".join(args),
                "exit_status": exit_status,
                "elapsed": elapsed_formatted,
                "utctimestamp": datetime.utcnow().replace(microsecond=0).isoformat(),
            },
        )
    else:
        print(f"--- Recorded calls (in {elapsed_formatted}) ---")
        for (call, callee) in recorded_calls:
            print(f"{call} --> {callee}")

    print("--- captured stdout ---")
    print(captured_stdout.getvalue(), end="")
    print("--- captured stderr ---")
    print(captured_stderr.getvalue(), end="")

    return 0
