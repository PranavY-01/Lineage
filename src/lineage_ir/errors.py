"""Typed errors raised by the engine and mapped to process exit codes by the CLI."""


class LineageError(Exception):
    """Base error; ``exit_code`` is the process exit code the CLI uses."""

    exit_code = 4


class UsageError(LineageError):
    """Bad option, unsupported input argument or unsafe output path (exit 2)."""

    exit_code = 2


class InputError(LineageError):
    """An input file is unusable as a whole (exit 3)."""

    exit_code = 3


class OutputError(LineageError):
    """A requested output could not be written (exit 4)."""

    exit_code = 4
