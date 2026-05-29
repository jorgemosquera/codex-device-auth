class AuthError(Exception):
    """Base error for authentication failures."""


class CredentialError(AuthError):
    """Raised when stored credentials cannot be used."""
