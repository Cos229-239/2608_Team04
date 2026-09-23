# Desktop chat recovery

The main Keeper conversation tracks chat completion separately from other UI
operations. A refresh or unrelated operation cannot dismiss its pending message.
Draft revisions protect newer editor text when an earlier send completes.
Secondary composers do not take ownership of an existing main-editor draft.

Draft edits are staged immediately and persisted after a short debounce. Normal
window close flushes staged text first; a storage failure cancels close and keeps
the editor available so the user can copy or save the text. Force termination or
power loss can still lose edits within the debounce interval.

A failed pre-send draft flush leaves the editor intact and does not start a send.
If draft cleanup fails after recording, completion still releases the busy state
and warns that a stale disk draft may remain. Do not resend that stale draft after
restart; disk-write failure prevents guaranteeing its removal.

When a conversation operation returns successfully but refreshing the view fails,
Keeper reports that the message was recorded and instructs the user to refresh,
not resend. If the operation itself raises, its outcome may be partial: the UI
asks the user to review the conversation before retrying. This does not change
provider authority, external-effect reconciliation, or execution recovery rules.

Verification: `tests/keeper/test_qml_desktop.py` covers controller boundaries;
`tests/keeper/test_chat_recovery_integration.py` loads the actual QML in a separate
offscreen GUI process and checks concurrency, draft restoration, projection loss,
close-time flushing, and failed-storage shutdown behavior.
