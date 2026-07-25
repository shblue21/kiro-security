"""SQLite-safe serialization for platform filesystem identity values."""


def serialize_filesystem_identity(value):
    # type: (int) -> object
    if -(1 << 63) <= value < (1 << 63):
        return value
    return "stat:%x" % value


def stored_filesystem_identity_matches(stored, current):
    # type: (object, int) -> bool
    return stored == serialize_filesystem_identity(current)
