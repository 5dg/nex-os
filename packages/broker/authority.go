package broker

import "context"

// ExecutionAuthority is the receiver's narrow Guard dependency. Readiness never
// grants execution; only AuthorizeEffect can admit a new provider/artifact effect.
type ExecutionAuthority interface {
	AuthorizeEffect(context.Context, string, string) error
	CompleteExecution(context.Context, string, string, any) error
	Readiness(context.Context) error
}
