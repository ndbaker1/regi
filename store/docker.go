package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/moby/client"
)

type dockerClient struct {
	*client.Client
}

// NewDockerClient creates a Store connected to the Docker daemon.
func NewDockerClient(ctx context.Context) (*dockerClient, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &dockerClient{cli}, nil
}

// Pull pulls ref from its upstream registry into our local docker store and
// blocks until the pull completes. This will wind up using whatever credentials
// the docker daemon is configured with.
func (s *dockerClient) Pull(ctx context.Context, ref string) error {
	resp, err := s.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("image pull %q: %w", ref, err)
	}
	// Wait drains the progress stream, closes it, and surfaces any error
	// reported by the daemon (e.g. not found, unauthorized).
	if err := resp.Wait(ctx); err != nil {
		return fmt.Errorf("image pull %q: %w", ref, err)
	}
	return nil
}

// buildDockerRef constructs a Docker-compatible image reference string from a
// repository path and a reference that may be a tag or a digest.
func (s *dockerClient) BuildRef(repo, ref string) (string, error) {
	// Try as digest first (e.g. "sha256:abc123...").
	if strings.Contains(ref, ":") {
		full := repo + "@" + ref
		if _, err := reference.Parse(full); err != nil {
			return "", fmt.Errorf("invalid digest reference %q: %w", full, err)
		}
		return full, nil
	}
	// Treat as tag.
	full := repo + ":" + ref
	if _, err := reference.ParseNormalizedNamed(full); err != nil {
		return "", fmt.Errorf("invalid tag reference %q: %w", full, err)
	}
	return full, nil
}
