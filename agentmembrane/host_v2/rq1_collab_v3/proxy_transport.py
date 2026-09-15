"""Bind one transport to the designated local proxy key, never ambient state."""
from ..rq1_collab_v1.providers import HTTPTransport, ProviderFailure


class BoundProxyTransport(HTTPTransport):
    def __init__(self, endpoint, credential_env, *, credential, **kwargs):
        super().__init__(endpoint, credential_env, **kwargs)
        self._bound_credential = credential
        self.prepare()

    def prepare(self):
        # ModelDriver intentionally prepares on each request. Revalidate the
        # private per-instance binding without exporting a process-wide key.
        key = self._bound_credential
        self._credential = None
        if type(key) is not str or not key:
            raise ProviderFailure("credential_unavailable", delivery="prepared_only", request_id="")
        if any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ProviderFailure("credential_invalid", delivery="prepared_only", request_id="")
        self._credential = key


def dedicated_proxy_transport(*, timeout_seconds=60):
    from ..rq1_collab_v1.live_pilot import load_proxy_key, proxy_base, proxy_credential_env
    return BoundProxyTransport(proxy_base() + "/chat/completions", proxy_credential_env(),
                               credential=load_proxy_key(), timeout_seconds=timeout_seconds,
                               hard_timeout_seconds=timeout_seconds)
