package main

import (
	"testing"
	"time"
)

func TestValidateConfig_MissingRequiredEnv(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")

	err := validateConfig()
	if err == nil {
		t.Fatalf("expected error when OPENROUTER_API_KEY is missing, got nil")
	}
}

func TestValidateConfig_WithRequiredEnv(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "test-key")

	err := validateConfig()
	if err != nil {
		t.Fatalf("expected no error when OPENROUTER_API_KEY is set, got: %v", err)
	}
}

func TestTimeoutConfigHelpers(t *testing.T) {
	// Defaults
	if getRequestTimeout() != 60*time.Second {
		t.Fatalf("expected default request timeout 60s, got %v", getRequestTimeout())
	}
	if getAITimeout() != 30*time.Second {
		t.Fatalf("expected default AI timeout 30s, got %v", getAITimeout())
	}
	if getVerifierTimeout() != 2*time.Second {
		t.Fatalf("expected default verifier timeout 2s, got %v", getVerifierTimeout())
	}

	// Custom values
	t.Setenv("REQUEST_TIMEOUT_SECONDS", "10")
	t.Setenv("AI_REQUEST_TIMEOUT_SECONDS", "5")
	t.Setenv("VERIFIER_TIMEOUT_SECONDS", "1")

	if getRequestTimeout() != 10*time.Second {
		t.Fatalf("expected request timeout 10s, got %v", getRequestTimeout())
	}
	if getAITimeout() != 5*time.Second {
		t.Fatalf("expected AI timeout 5s, got %v", getAITimeout())
	}
	if getVerifierTimeout() != 1*time.Second {
		t.Fatalf("expected verifier timeout 1s, got %v", getVerifierTimeout())
	}
}