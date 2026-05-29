class AuthError(Exception):
    """Base error for authentication failures."""


class CredentialError(AuthError):
    """Raised when stored credentials cannot be used."""


class DeviceCodeError(AuthError):
    """Raised when device-code authentication fails."""


class DeviceCodeDeniedError(DeviceCodeError):
    """Raised when the user denies the device-code authorization."""


class DeviceCodeNetworkError(DeviceCodeError):
    """Raised when a provider request fails."""


class DeviceCodeResponseError(DeviceCodeError):
    """Raised when the provider returns an invalid device-code response."""


class DeviceCodeTimeoutError(DeviceCodeError):
    """Raised when polling reaches its bounded timeout."""
