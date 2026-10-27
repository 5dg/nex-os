// Package trust implements the synthetic qualification transport contract. It
// does not enable production or assert validated cryptographic-module status.
package trust

import (
	"errors"
	"os"
)

type Profile string

const (
	Development   Profile = "development"
	Qualification Profile = "synthetic-qualification"
)

func ParseProfile(raw string) (Profile, error) {
	switch raw {
	case "", string(Development):
		return Development, nil
	case string(Qualification):
		return Qualification, nil
	default:
		return "", errors.New("unsupported profile; production remains closed")
	}
}
func FromEnv() (Profile, error) { return ParseProfile(os.Getenv("NEX_PROFILE")) }

type Role string

const (
	Workspace Role = "workspace"
	Control   Role = "control"
	Guard     Role = "guard"
	Model     Role = "model"
	Export    Role = "export"
	Evidence  Role = "evidence"
	Worker    Role = "worker"
	OPA       Role = "opa"
	OIDC      Role = "oidc"
)

func (r Role) URI() string { return "spiffe://nex.local/service/" + string(r) }
func (r Role) Valid() bool {
	switch r {
	case Workspace, Control, Guard, Model, Export, Evidence, Worker, OPA, OIDC:
		return true
	}
	return false
}
