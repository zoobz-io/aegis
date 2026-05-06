package aegis

// Auditable defines the contract for events that can be recorded as domain events.
// Source app event types implement this so the herald aegis provider can extract
// structured envelope fields for indexing.
type Auditable interface {
	Action() string
	ResourceType() string
	ResourceID() string
	TenantID() string
	ActorID() string
	Message() string
	Attributes() map[string]string
}
