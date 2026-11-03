"""The allow-list of checks, and validation of their arguments.

This is the agent's only route to a host. The model can name a check and its
arguments, but it never supplies a command.
"""

from .probe import DIRECTIVE_RE, PACKAGE_RE, VERSION_RE, allowed_config_path

EXPECTED_ARGS = {
    "package_status": {"package"},
    "package_runtime": {"package"},
    "version_at_least": {"package", "version"},
    "config_directive": {"path", "directive"},
}

# The checks the model may ask for. version_at_least is left out because it always runs first.
MODEL_CHECKS = {
    "package_status": "Is a package installed, and at which version? args: package",
    "package_runtime": "What is a package doing now: processes, libraries, services, listeners? args: package",
    "config_directive": "Find active lines setting a directive in a config file or folder under /etc. args: path, directive",
}


class CheckRejected(ValueError):
    """The requested check or its arguments are outside the allow-list."""


def validate(check, args):
    """Return the arguments if they're allowed. Otherwise raise CheckRejected."""
    expected = EXPECTED_ARGS.get(check)
    if expected is None:
        raise CheckRejected(f"check is not on the allow-list: {check!r}")
    if not isinstance(args, dict) or set(args) != expected:
        raise CheckRejected(f"{check} needs exactly these arguments: {sorted(expected)}")
    if not all(isinstance(value, str) for value in args.values()):
        raise CheckRejected("check arguments must be strings")
    if "package" in args and not PACKAGE_RE.match(args["package"]):
        raise CheckRejected(f"invalid package name: {args['package']!r}")
    if "version" in args and not VERSION_RE.match(args["version"]):
        raise CheckRejected(f"invalid version: {args['version']!r}")
    if "directive" in args and not DIRECTIVE_RE.match(args["directive"]):
        raise CheckRejected(f"invalid directive: {args['directive']!r}")
    if "path" in args and not allowed_config_path(args["path"]):
        raise CheckRejected(f"path is not allowed: {args['path']!r}")
    return args
