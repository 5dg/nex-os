package contracts

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
)

// ExecutionDigest v2 hashes semantic UTF-8 fields, never serialized JSON/Protobuf.
// Fields are prefixed by their byte length as an unsigned big-endian u64.
func ExecutionDigest(v any) string {
	var fields []string
	version := 2
	switch x := v.(type) {
	case Export:
		if x.ManifestVersion != 0 && x.ManifestVersion != 2 && x.ManifestVersion != 3 {
			return ""
		}
		fields = []string{"export", x.OperationID, x.TenantID, x.DestinationID, x.Content, x.RequestDigest}
		if x.ManifestVersion == 3 {
			version = 3
			fields = append([]string{"export", "3"}, fields[1:]...)
		}
	case Generation:
		if x.ManifestVersion != 0 && x.ManifestVersion != 2 && x.ManifestVersion != 3 {
			return ""
		}
		fields = []string{"model", x.OperationID, x.TenantID, x.RouteID, x.Classification, x.Prompt, strconv.Itoa(x.MaxTokens)}
		if x.ManifestVersion == 3 {
			version = 3
			fields = append([]string{"model", "3"}, fields[1:]...)
			fields = append(fields, x.Provider, x.Region, x.ModelID, x.EffectiveEndpoint, x.TemplateVersion, x.QuestionCatalogueID, x.QuestionCatalogueVersion, x.QuestionClassification)
			features := append([]string(nil), x.Features...)
			sort.Strings(features)
			fields = append(fields, strconv.Itoa(len(features)))
			fields = append(fields, features...)
		}
	default:
		panic("unsupported execution payload")
	}
	b := []byte("nex.execution.payload.v" + strconv.Itoa(version) + "\x00")
	for _, f := range fields {
		b = binary.BigEndian.AppendUint64(b, uint64(len([]byte(f))))
		b = append(b, []byte(f)...)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
