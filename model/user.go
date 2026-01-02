// Package model provides data models for the PDVD system.
package model

import (
	"time"
)

// User represents a user in the system
type User struct {
	Key          string    `json:"_key,omitempty"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash,omitempty"`
	Role         string    `json:"role"` // admin, editor, viewer
	IsActive     bool      `json:"is_active"`
	Status       string    `json:"status"` // pending, active, inactive
	AuthProvider string    `json:"auth_provider"` // local, oidc
	ExternalID   string    `json:"external_id,omitempty"` // For OIDC
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Invitation represents a user invitation
type Invitation struct {
	Key        string    `json:"_key,omitempty"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Token      string    `json:"token"` // Secure random token
	Role       string    `json:"role"`
	ExpiresAt  time.Time `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	ResendCount int      `json:"resend_count"`
}

// NewUser creates a new user with default values
func NewUser(username, role string) *User {
	now := time.Now()
	return &User{
		Username:     username,
		Role:         role,
		IsActive:     true,
		Status:       "pending", // Default to pending until invitation accepted
		AuthProvider: "local",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// NewInvitation creates a new invitation
func NewInvitation(username, email, token, role string) *Invitation {
	now := time.Now()
	return &Invitation{
		Username:    username,
		Email:       email,
		Token:       token,
		Role:        role,
		ExpiresAt:   now.Add(48 * time.Hour), // 48 hour expiry
		CreatedAt:   now,
		ResendCount: 0,
	}
}

// IsExpired checks if invitation has expired
func (i *Invitation) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// IsAccepted checks if invitation has been accepted
func (i *Invitation) IsAccepted() bool {
	return i.AcceptedAt != nil
}
