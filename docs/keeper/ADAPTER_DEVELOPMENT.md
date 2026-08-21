# Adapter Development

Implement `AgentProvider.validate()` and `run(AgentRequest)`. Give each instance a
stable identity; expose capability/version/health diagnostics; use argument arrays;
constrain the working directory; bound and redact logs; return provider failure
without translating it into task success; and use the common process-tree cleanup
runner for command providers.

Add deterministic tests for command construction, malformed output, timeout,
cancellation, descendant cleanup, unavailability, and independence. Never store
credentials in settings or evidence.
