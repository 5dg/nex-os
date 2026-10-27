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
