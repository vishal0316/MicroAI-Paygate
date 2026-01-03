package main

import (
	"os"
	"testing"
)

func TestValidateConfig_MissingRequiredEnv(t *testing.T) {
	// Ensure env var is not set
	os.Unsetenv("OPENROUTER_API_KEY")

	err := validateConfig()
	if err == nil {
		t.Fatalf("Expected error when OPENROUTER_API_KEY is missing, got nil")
	}
}

func TestValidateConfig_WithRequiredEnv(t *testing.T) {
	// Set required environment variables
	os.Setenv("OPENROUTER_API_KEY", "test-key")

	err := validateConfig()
	if err != nil {
		t.Fatalf("Expected no error when all required environment variables are set, got: %v", err)
	}
}