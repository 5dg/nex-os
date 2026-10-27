package contracts

// Trusted facts never come from these request fields. Control resolves them.
type ActionRequest struct {
	DelegationID string `json:"delegation_id"`
	Action       string `json:"action"`
	ResourceID   string `json:"resource_id"`
}

type Decision struct {
	ID            string `json:"decision_id"`
	Effect        string `json:"effect"`
	Reason        string `json:"reason_code"`
	PolicyVersion string `json:"policy_version"`
	PolicyDigest  string `json:"policy_digest"`
}

type Error struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type Delegation struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
	ExpiresAt   string   `json:"expires_at"`
	RevokedAt   *string  `json:"revoked_at,omitempty"`
}

type Job struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	DelegationID string `json:"delegation_id"`
	State        string `json:"state"`
}

type Approval struct {
	ID            string  `json:"id"`
	TenantID      string  `json:"tenant_id"`
	RequestDigest string  `json:"request_digest"`
	ExpiresAt     string  `json:"expires_at"`
	ConsumedAt    *string `json:"consumed_at,omitempty"`
}

type ModelInvocation struct {
	DelegationID    string `json:"delegation_id"`
	ResourceID      string `json:"resource_id"`
	Prompt          string `json:"prompt"`
	MaxOutputTokens int    `json:"max_output_tokens"`
}

type ModelResult struct {
	Provider   string `json:"provider"`
	ModelID    string `json:"model_id"`
	Text       string `json:"text"`
	DecisionID string `json:"decision_id"`
}

type DocumentReference struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	Classification string `json:"classification"`
	Version        string `json:"version"`
}

type AuditEvent struct {
	ID           string   `json:"event_id"`
	TenantID     string   `json:"tenant_id"`
	ActorID      string   `json:"actor_id"`
	DelegationID string   `json:"delegation_id"`
	Action       string   `json:"action"`
	ResourceID   string   `json:"resource_id"`
	Decision     Decision `json:"decision"`
}
