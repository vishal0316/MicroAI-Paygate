package main

import "time"

// Timeout helpers (configurable via env vars)
func getRequestTimeout() time.Duration {
	seconds := getEnvAsInt("REQUEST_TIMEOUT_SECONDS", 60)
	return time.Duration(seconds) * time.Second
}

func getAITimeout() time.Duration {
	seconds := getEnvAsInt("AI_REQUEST_TIMEOUT_SECONDS", 30)
	return time.Duration(seconds) * time.Second
}

func getVerifierTimeout() time.Duration {
	seconds := getEnvAsInt("VERIFIER_TIMEOUT_SECONDS", 2)
	return time.Duration(seconds) * time.Second
}

func getHealthCheckTimeout() time.Duration {
	seconds := getEnvAsInt("HEALTH_CHECK_TIMEOUT_SECONDS", 2)
	return time.Duration(seconds) * time.Second
}
