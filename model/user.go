// Package model - User defines the struct for user profie
package model

import "time"

// User represents a user in the system
type User struct {
	Key          string    `json:"_key,omitempty"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash,omitempty"` // Empty if using OIDC
	Email        string    `json:"email"`
	Role         string    `json:"role"`          // admin, editor, viewer
	IsActive     bool      `json:"is_active"`     // true/false
	AuthProvider string    `json:"auth_provider"` // "local" or "oidc"
	ExternalID   string    `json:"external_id,omitempty"`
	ObjType      string    `json:"objtype,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NewUser creates a User with defaults
func NewUser(username, role string) *User {
	now := time.Now()
	return &User{
		Username:     username,
		Role:         role,
		IsActive:     true,
		AuthProvider: "local",
		ObjType:      "User",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
