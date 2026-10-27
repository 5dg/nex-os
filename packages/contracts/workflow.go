package contracts

type CreateJob struct {
	QuestionCatalogueID string `json:"question_catalogue_id,omitempty"`
	DelegationID        string `json:"delegation_id"`
	DocumentID          string `json:"document_id"`
	Question            string `json:"question"`
	IdempotencyKey      string `json:"idempotency_key"`
}
type ReviewJob struct {
	QuestionCatalogueID      string `json:"question_catalogue_id,omitempty"`
	QuestionCatalogueVersion string `json:"question_catalogue_version,omitempty"`
	ID                       string `json:"id"`
	TenantID                 string `json:"tenant_id"`
	State                    string `json:"state"`
	Phase                    string `json:"phase"`
	DocumentID               string `json:"document_id"`
	DocumentVersion          string `json:"document_version"`
	Question                 string `json:"question"`
	Answer                   string `json:"answer,omitempty"`
	Provider                 string `json:"provider,omitempty"`
	Citation                 string `json:"citation,omitempty"`
	ErrorCode                string `json:"error_code,omitempty"`
	ApprovalID               string `json:"approval_id,omitempty"`
	ExportID                 string `json:"export_id,omitempty"`
}
type Lease struct {
	JobID string `json:"job_id"`
	Token string `json:"lease_token"`
}
type Generation struct {
	ManifestVersion          int      `json:"manifest_version,omitempty"`
	Provider                 string   `json:"provider,omitempty"`
	Region                   string   `json:"region,omitempty"`
	ModelID                  string   `json:"model_id,omitempty"`
	EffectiveEndpoint        string   `json:"effective_endpoint,omitempty"`
	Features                 []string `json:"features,omitempty"`
	TemplateVersion          string   `json:"template_version,omitempty"`
	QuestionCatalogueID      string   `json:"question_catalogue_id,omitempty"`
	QuestionCatalogueVersion string   `json:"question_catalogue_version,omitempty"`
	QuestionClassification   string   `json:"question_classification,omitempty"`
	OperationID              string   `json:"operation_id"`
	TenantID                 string   `json:"tenant_id"`
	RouteID                  string   `json:"route_id"`
	Classification           string   `json:"classification"`
	Prompt                   string   `json:"prompt"`
	MaxTokens                int      `json:"max_tokens"`
}
type GenerationResult struct {
	Text     string `json:"text"`
	Provider string `json:"provider"`
	ModelID  string `json:"model_id"`
}
type Export struct {
	ManifestVersion int    `json:"manifest_version,omitempty"`
	OperationID     string `json:"operation_id"`
	TenantID        string `json:"tenant_id"`
	DestinationID   string `json:"destination_id"`
	Content         string `json:"content"`
	RequestDigest   string `json:"request_digest"`
}
type ExportResult struct {
	ArtifactID    string `json:"artifact_id"`
	ContentDigest string `json:"content_digest"`
}
type ValidateOperation struct {
	OperationID   string `json:"operation_id"`
	RequestDigest string `json:"request_digest"`
}
type OperationValidation struct {
	Allowed bool `json:"allowed"`
}
type ExportRequest struct {
	DestinationID string `json:"destination_id"`
}
type ApprovalDecision struct {
	Approve       bool   `json:"approve"`
	RequestDigest string `json:"request_digest"`
}
type ApprovalView struct {
	RequesterID     string `json:"requester_id,omitempty"`
	DocumentID      string `json:"document_id,omitempty"`
	DocumentVersion string `json:"document_version,omitempty"`
	ExportPreview   string `json:"export_preview,omitempty"`
	ID              string `json:"id"`
	JobID           string `json:"job_id"`
	RequestDigest   string `json:"request_digest"`
	DestinationID   string `json:"destination_id"`
	ExpiresAt       string `json:"expires_at"`
	Status          string `json:"status"`
}

type IdentityView struct {
	Issuer       string   `json:"issuer"`
	Subject      string   `json:"subject"`
	UserID       string   `json:"user_id"`
	TenantID     string   `json:"tenant_id"`
	DelegationID string   `json:"delegation_id"`
	Permissions  []string `json:"permissions"`
}
