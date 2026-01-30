package httpclient

import (
	"fmt"
	"strings"
	"testing"
)

// TestSecureString_PreventLeakage verifies that SecureString prevents accidental
// secret leakage through various fmt formatting operations.
func TestSecureString_PreventLeakage(t *testing.T) {
	secret := "super-secret-password-123"
	secureString := NewSecureString(secret)

	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "fmt.Sprint",
			output: fmt.Sprint(secureString),
		},
		{
			name:   "fmt.Sprintf with %v",
			output: fmt.Sprintf("%v", secureString),
		},
		{
			name:   "String() method directly",
			output: secureString.String(),
		},
		{
			name:   "fmt.Sprintf with %+v",
			output: fmt.Sprintf("%+v", secureString),
		},
		{
			name:   "fmt.Sprintf with %#v",
			output: fmt.Sprintf("%#v", secureString),
		},
		{
			name:   "String() method",
			output: secureString.String(),
		},
		{
			name:   "GoString() method",
			output: secureString.GoString(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the actual secret is NOT present in the output
			if strings.Contains(tt.output, secret) {
				t.Errorf("%s leaked the secret: got %q, should not contain %q",
					tt.name, tt.output, secret)
			}

			// Verify the output contains the redacted marker
			if !strings.Contains(tt.output, "***REDACTED***") {
				t.Errorf("%s did not redact secret: got %q, want to contain '***REDACTED***'",
					tt.name, tt.output)
			}
		})
	}
}

// TestSecureString_AuthConfigLeakage tests that AuthConfig with SecureString
// does not leak secrets when printed.
func TestSecureString_AuthConfigLeakage(t *testing.T) {
	secret := "my-api-secret-key-456" //nolint:gosec // test data
	config := NewAuthConfig(AuthModeSimple, secret)

	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "fmt.Printf with %v",
			output: fmt.Sprintf("%v", config),
		},
		{
			name:   "fmt.Printf with %+v",
			output: fmt.Sprintf("%+v", config),
		},
		{
			name:   "fmt.Printf with %#v",
			output: fmt.Sprintf("%#v", config),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Verify the actual secret is NOT present in the output
			if strings.Contains(tt.output, secret) {
				t.Errorf("%s leaked the secret: got %q, should not contain %q",
					tt.name, tt.output, secret)
			}

			// Verify the output contains the redacted marker
			if !strings.Contains(tt.output, "***REDACTED***") {
				t.Errorf("%s did not redact secret: got %q, want to contain '***REDACTED***'",
					tt.name, tt.output)
			}
		})
	}
}

// TestSecureString_Bytes verifies that the Bytes() method correctly returns
// the actual secret value for internal use.
func TestSecureString_Bytes(t *testing.T) {
	secret := "test-secret-789"
	secureString := NewSecureString(secret)

	// Verify Bytes() returns the actual value
	if string(secureString.Bytes()) != secret {
		t.Errorf("Bytes() = %q, want %q", string(secureString.Bytes()), secret)
	}
}

// TestSecureString_IsEmpty verifies the IsEmpty() method.
func TestSecureString_IsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "Empty string",
			value: "",
			want:  true,
		},
		{
			name:  "Non-empty string",
			value: "secret",
			want:  false,
		},
		{
			name:  "Whitespace string",
			value: " ",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secureString := NewSecureString(tt.value)
			if got := secureString.IsEmpty(); got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSecureString_ZeroStruct verifies behavior with zero-value SecureString.
func TestSecureString_ZeroStruct(t *testing.T) {
	var secureString SecureString

	// Zero value should be empty
	if !secureString.IsEmpty() {
		t.Errorf("Zero-value SecureString should be empty")
	}

	// Zero value should still redact when printed
	output := fmt.Sprintf("%v", secureString)
	if !strings.Contains(output, "***REDACTED***") {
		t.Errorf("Zero-value SecureString should still redact: got %q", output)
	}
}
