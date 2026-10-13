"""Distinct structural, protocol-rejection and unimplemented failure domains."""


class MyABE08Error(Exception):
    """Base exception; never interpreted as an authorization success."""


class ContractError(MyABE08Error, ValueError):
    """Malformed structural input (not a cryptographic verification result)."""


class AuthenticationError(MyABE08Error):
    """Controlled AEAD authentication failure; no plaintext is released."""


class BackendValidationError(ContractError):
    """Noncanonical, wrong-group, wrong-subgroup or cross-binding object."""


class UnsupportedProfileError(ContractError):
    """Unknown profile, wrong profile axis, or incompatible profile metadata."""


class AlgorithmNotImplementedError(MyABE08Error, NotImplementedError):
    """An intentionally unavailable Phase 1 operation, not protocol bottom."""


class BackendNotImplementedError(AlgorithmNotImplementedError):
    """A named pairing profile has no verified MYABE-08 adapter."""


class ProtocolRejectedError(MyABE08Error):
    """Future protocol bottom: authentication/state/policy rejection."""


class StateSynchronizationError(ProtocolRejectedError):
    """No fresh linearizable current-head permit, gap, or rollback detected."""


class ReplayRejectedError(ProtocolRejectedError):
    """Request issuance or consumption cannot proceed atomically."""


class AFBuildError(ProtocolRejectedError):
    """Finite seed budget exhausted; no partial filter may escape."""


def unimplemented(operation: str) -> None:
    raise AlgorithmNotImplementedError(
        "MYABE-08 protocol scaffold: %s is not implemented" % operation
    )


class UnsupportedPolicy(ContractError):
    """Policy exceeds structural profile constraints."""


class Unauthorized(ProtocolRejectedError):
    """Target vector is outside the supplied candidate row span."""
