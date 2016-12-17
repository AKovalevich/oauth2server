package oauth

import (
	"time"
)

// TokenResponse is the authorization server response
type TokenResponse struct {
	Token        string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	TokenType    string            `json:"token_type"` // bearer
	ExperesIn    int64             `json:"expires_in"` // secs
	Properties   map[string]string `json:"properties"`
}

// Token structure generated by the authorization server
type Token struct {
	Id           string            `json:"id"`
	CreationDate time.Time         `json:"date"`
	ExperesIn    time.Duration     `json:"expires_in"` // secs
	Credential   string            `json:"credential"`
	Claims       map[string]string `json:"claims"`
	TokenType    string            `json:"type"` // "U" for user, "C" for client
}

// RefreshToken structure included in the authorization server response
type RefreshToken struct {
	CreationDate time.Time `json:"date"`
	TokenId      string    `json:"id"`
	Credential   string    `json:"credential"`
	TokenType    string    `json:"type"` // "U" for user, "C" for client
}