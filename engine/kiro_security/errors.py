"""Typed workbench failures."""


class WorkbenchError(RuntimeError):
    """A stable, user-safe contract failure."""

    def __init__(self, code, message):
        # type: (str, str) -> None
        super().__init__(message)
        self.code = code
