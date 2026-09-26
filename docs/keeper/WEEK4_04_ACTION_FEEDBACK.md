# Update 4 - preserve successful actions when refresh fails

The generic desktop action wrapper previously let a post-action projection
exception escape after the service had already returned successfully. It now
distinguishes that condition from a failed service call: retain the last snapshot,
show the specific action's success followed by a refresh warning, emit one
successful completion, and instruct the user to Refresh rather than repeat it.

Service failures still emit failure. No operation is automatically retried, no
authorization checks are removed, and conversation completion/drafts are not
touched. Refresh only reloads the view. Failure details in this warning are
constant public text, not raw database paths.

Regression cases cover repair creation, pause, report export, authorization
revocation, and an actual local provider-path save, plus operation/refresh failure
boundaries. Service methods in effectful tests are stubs; no live effect occurs.
