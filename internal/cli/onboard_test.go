package cli

import (
	"testing"
)

func TestExtractClusterName(t *testing.T) {
	tests := []struct {
		name   string
		apiURL string
		want   string
	}{
		{
			name:   "standard OCP URL with port",
			apiURL: "https://api.my-cluster.example.com:6443",
			want:   "my-cluster",
		},
		{
			name:   "standard OCP URL without port",
			apiURL: "https://api.my-cluster.example.com",
			want:   "my-cluster",
		},
		{
			name:   "http scheme",
			apiURL: "http://api.my-cluster.example.com:6443",
			want:   "my-cluster",
		},
		{
			name:   "multi-segment domain",
			apiURL: "https://api.prod-ocp.us-east-1.cloud.example.com:6443",
			want:   "prod-ocp",
		},
		{
			name:   "no api prefix",
			apiURL: "https://my-cluster.example.com:6443",
			want:   "",
		},
		{
			name:   "api with two segments after",
			apiURL: "https://api.example.com",
			want:   "example",
		},
		{
			name:   "api with only one segment after",
			apiURL: "https://api.example",
			want:   "",
		},
		{
			name:   "empty string",
			apiURL: "",
			want:   "",
		},
		{
			name:   "no scheme",
			apiURL: "api.my-cluster.example.com:6443",
			want:   "my-cluster",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractClusterName(tt.apiURL)
			if got != tt.want {
				t.Errorf("extractClusterName(%q) = %q, want %q", tt.apiURL, got, tt.want)
			}
		})
	}
}

func TestBuildOnboardPayload(t *testing.T) {
	// Save and restore globals
	origPurpose := onboardPurpose
	origAnnotations := onboardAnnotations
	origConfigFile := onboardConfigFile
	defer func() {
		onboardPurpose = origPurpose
		onboardAnnotations = origAnnotations
		onboardConfigFile = origConfigFile
	}()

	t.Run("basic payload", func(t *testing.T) {
		onboardPurpose = "dev"
		onboardAnnotations = ""
		onboardConfigFile = ""

		payload, err := buildOnboardPayload("test-cluster", "https://api.test.example.com:6443", "apps.test.example.com", "token123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if payload["name"] != "test-cluster" {
			t.Errorf("name = %v, want test-cluster", payload["name"])
		}
		if payload["api_url"] != "https://api.test.example.com:6443" {
			t.Errorf("api_url = %v, want https://api.test.example.com:6443", payload["api_url"])
		}
		if payload["ingress_domain"] != "apps.test.example.com" {
			t.Errorf("ingress_domain = %v, want apps.test.example.com", payload["ingress_domain"])
		}
		if payload["token"] != "token123" {
			t.Errorf("token = %v, want token123", payload["token"])
		}

		annotations, ok := payload["annotations"].(map[string]any)
		if !ok {
			t.Fatalf("annotations not a map: %T", payload["annotations"])
		}
		if annotations["purpose"] != "dev" {
			t.Errorf("annotations.purpose = %v, want dev", annotations["purpose"])
		}
		if annotations["name"] != "test-cluster" {
			t.Errorf("annotations.name = %v, want test-cluster", annotations["name"])
		}
	})

	t.Run("with extra annotations", func(t *testing.T) {
		onboardPurpose = "prod"
		onboardAnnotations = `{"cloud":"aws-shared","virt":"yes"}`
		onboardConfigFile = ""

		payload, err := buildOnboardPayload("my-cluster", "https://api.my.example.com:6443", "apps.my.example.com", "tok")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		annotations, ok := payload["annotations"].(map[string]any)
		if !ok {
			t.Fatalf("annotations not a map: %T", payload["annotations"])
		}
		if annotations["purpose"] != "prod" {
			t.Errorf("annotations.purpose = %v, want prod", annotations["purpose"])
		}
		if annotations["cloud"] != "aws-shared" {
			t.Errorf("annotations.cloud = %v, want aws-shared", annotations["cloud"])
		}
		if annotations["virt"] != "yes" {
			t.Errorf("annotations.virt = %v, want yes", annotations["virt"])
		}
	})

	t.Run("invalid annotations JSON", func(t *testing.T) {
		onboardPurpose = "dev"
		onboardAnnotations = "not-json"
		onboardConfigFile = ""

		_, err := buildOnboardPayload("c", "u", "d", "t")
		if err == nil {
			t.Fatal("expected error for invalid JSON annotations")
		}
	})
}
