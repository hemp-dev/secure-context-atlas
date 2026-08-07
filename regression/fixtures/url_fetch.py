"""Synthetic-only fixture: the URL is a placeholder, not a network target."""


def review_only_fetch(request_url: str, client, policy):
    # The regression fixture models a source-to-sink flow for a detector.
    # Tests must provide a local mock client and a rejecting policy.
    if policy.allows(request_url):
        return client.fetch(request_url)
    return {"status": "blocked", "canary": True}
