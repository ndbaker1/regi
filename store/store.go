package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/distribution/reference"
	"github.com/moby/moby/client"
	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// mediaTypeDockerManifest is the Docker v2 schema 2 manifest media type.
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"

	// ociSchemaVersion is the OCI image manifest schema version.
	ociSchemaVersion = 2

	// dockerManifestFile is the manifest filename in Docker-format tar archives.
	dockerManifestFile = "manifest.json"

	// blobsSHA256Prefix is the path prefix for content-addressable blobs in OCI layouts.
	blobsSHA256Prefix = "blobs/sha256/"
)

// Descriptor describes a content-addressable blob.
type Descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// Manifest is an OCI image manifest.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// Index is an OCI image index (manifest list).
type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

// imageContent holds the extracted content from a single image save.
type imageContent struct {
	// blobs maps "sha256:<hex>" -> raw bytes for configs, layers, and manifests.
	blobs map[string][]byte
	// manifestDigest is the digest of the synthesized OCI manifest.
	manifestDigest string
}

// TODO: make these actually generic.
type StoreClient interface {
	ImageList(context.Context, client.ImageListOptions) (client.ImageListResult, error)
	ImageSave(context.Context, []string, ...client.ImageSaveOption) (client.ImageSaveResult, error)
	ImageInspect(context.Context, string, ...client.ImageInspectOption) (client.ImageInspectResult, error)
	BuildRef(repo, ref string) (string, error)
}

// Store talks to the storage backend and translates its image store into OCI
// registry content. It is stateless; each call extracts fresh data.
type Store struct {
	client StoreClient
	log    *slog.Logger
}

func NewStore(client StoreClient, log *slog.Logger) *Store {
	return &Store{client: client, log: log}
}

// resolveFullRef resolves a repo path + ref (tag or digest) to a full Docker
// reference that ImageSave will accept. It tries the bare ref first; if Docker
// doesn't recognise it, it queries the image list for entries whose path
// component matches and retries with each domain-qualified variant.
func (s *Store) resolveFullRef(ctx context.Context, repo, ref string) (string, error) {
	bare, err := s.client.BuildRef(repo, ref)
	if err != nil {
		return "", err
	}

	// Fast path: Docker already knows this exact reference.
	if _, err := s.client.ImageInspect(ctx, bare); err == nil {
		return bare, nil
	}

	// Slow path: scan the image list for entries whose path matches and try
	// each domain-qualified variant.
	result, err := s.client.ImageList(ctx, client.ImageListOptions{All: true})
	if err != nil {
		return "", fmt.Errorf("image list: %w", err)
	}

	for _, img := range result.Items {
		for _, rt := range img.RepoTags {
			named, err := reference.ParseNormalizedNamed(rt)
			if err != nil {
				continue
			}
			if reference.Path(named) != repo {
				continue
			}
			// Path matches — reconstruct with the requested tag/digest.
			base := reference.Domain(named) + "/" + reference.Path(named)
			candidate, err := s.client.BuildRef(base, ref)
			if err != nil {
				continue
			}
			if _, err := s.client.ImageInspect(ctx, candidate); err == nil {
				s.log.Debug("resolved ref", "bare", bare, "full", candidate)
				return candidate, nil
			}
		}
	}

	return "", fmt.Errorf("reference does not exist: %s", bare)
}

// Repositories returns all unique repository names in the local Docker store.
func (s *Store) Repositories(ctx context.Context) ([]string, error) {
	result, err := s.client.ImageList(ctx, client.ImageListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("image list: %w", err)
	}
	seen := map[string]struct{}{}
	var repos []string
	for _, img := range result.Items {
		for _, rt := range img.RepoTags {
			repo, _, err := parseRepoTag(rt)
			if err != nil {
				continue
			}
			if _, exists := seen[repo]; !exists {
				seen[repo] = struct{}{}
				repos = append(repos, repo)
			}
		}
	}
	return repos, nil
}

// Tags returns all tags for a given repository name.
func (s *Store) Tags(ctx context.Context, repo string) ([]string, error) {
	result, err := s.client.ImageList(ctx, client.ImageListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("image list: %w", err)
	}
	var tags []string
	for _, img := range result.Items {
		for _, rt := range img.RepoTags {
			r, t, err := parseRepoTag(rt)
			if err != nil {
				continue
			}
			if r == repo {
				tags = append(tags, t)
			}
		}
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("repository not found: %s", repo)
	}
	return tags, nil
}

// ResolveManifest returns the manifest bytes, its digest, and media type for
// the given repository and reference (tag or digest).
func (s *Store) ResolveManifest(ctx context.Context, repo, ref string) ([]byte, string, string, error) {
	// Digest references (sha256:...) can't be passed to Docker directly —
	// they're OCI manifest digests we computed, not Docker image IDs.
	// Resolve them by extracting each tag and checking the manifest digest.
	if strings.HasPrefix(ref, godigest.SHA256.String()+":") {
		return s.resolveManifestByDigest(ctx, repo, ref)
	}

	dockerRef, err := s.resolveFullRef(ctx, repo, ref)
	if err != nil {
		return nil, "", "", err
	}

	ic, err := s.extractImage(ctx, dockerRef)
	if err != nil {
		return nil, "", "", err
	}

	manifestBytes, ok := ic.blobs[ic.manifestDigest]
	if !ok {
		return nil, "", "", fmt.Errorf("manifest not found after extraction")
	}

	return manifestBytes, ic.manifestDigest, ocispec.MediaTypeImageManifest, nil
}

// resolveManifestByDigest finds a manifest by its content digest. It extracts
// each tagged image in the repo and checks whether the computed manifest digest
// matches the requested one.
func (s *Store) resolveManifestByDigest(ctx context.Context, repo, digest string) ([]byte, string, string, error) {
	tags, err := s.Tags(ctx, repo)
	if err != nil {
		return nil, "", "", err
	}

	for _, tag := range tags {
		ref, err := s.resolveFullRef(ctx, repo, tag)
		if err != nil {
			continue
		}
		ic, err := s.extractImage(ctx, ref)
		if err != nil {
			continue
		}
		if ic.manifestDigest == digest {
			manifestBytes, ok := ic.blobs[digest]
			if !ok {
				continue
			}
			return manifestBytes, digest, ocispec.MediaTypeImageManifest, nil
		}
		// Also check if the digest matches any blob (could be an inner
		// manifest in a multi-arch image).
		if data, ok := ic.blobs[digest]; ok {
			return data, digest, ocispec.MediaTypeImageManifest, nil
		}
	}
	return nil, "", "", fmt.Errorf("manifest not found: %s@%s", repo, digest)
}

// GetBlob returns the raw bytes for a content-addressable blob (config or layer).
func (s *Store) GetBlob(ctx context.Context, repo, digest string) ([]byte, error) {
	tags, err := s.Tags(ctx, repo)
	if err != nil {
		return nil, err
	}

	for _, tag := range tags {
		ref, err := s.resolveFullRef(ctx, repo, tag)
		if err != nil {
			continue
		}
		ic, err := s.extractImage(ctx, ref)
		if err != nil {
			continue
		}
		if data, ok := ic.blobs[digest]; ok {
			return data, nil
		}
	}
	return nil, fmt.Errorf("blob not found: %s", digest)
}

// HasBlob checks whether a blob with the given digest exists for the repo.
func (s *Store) HasBlob(ctx context.Context, repo, digest string) (int64, bool) {
	tags, err := s.Tags(ctx, repo)
	if err != nil {
		return 0, false
	}
	for _, tag := range tags {
		ref, err := s.resolveFullRef(ctx, repo, tag)
		if err != nil {
			continue
		}
		ic, err := s.extractImage(ctx, ref)
		if err != nil {
			continue
		}
		if data, ok := ic.blobs[digest]; ok {
			return int64(len(data)), true
		}
	}
	return 0, false
}

// extractImage calls ImageSave and parses the resulting tar archive into
// content-addressable blobs and an OCI manifest.
func (s *Store) extractImage(ctx context.Context, ref string) (*imageContent, error) {
	s.log.Debug("extracting image", "ref", ref)

	rc, err := s.client.ImageSave(ctx, []string{ref})
	if err != nil {
		return nil, fmt.Errorf("image save %q: %w", ref, err)
	}
	defer rc.Close()

	// Read entire tar into memory for parsing.
	tarBytes, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read tar: %w", err)
	}

	files, err := readTarFiles(bytes.NewReader(tarBytes))
	if err != nil {
		return nil, fmt.Errorf("read tar files: %w", err)
	}

	if _, ok := files[ocispec.ImageLayoutFile]; ok {
		return s.extractOCILayout(files)
	}
	return s.extractDockerFormat(files)
}

// extractOCILayout handles tars in OCI image layout format.
func (s *Store) extractOCILayout(files map[string][]byte) (*imageContent, error) {
	ic := &imageContent{
		blobs: make(map[string][]byte),
	}

	// Load all blobs from blobs/sha256/*.
	for name, data := range files {
		if hex, ok := strings.CutPrefix(name, blobsSHA256Prefix); ok {
			hex = strings.TrimSuffix(hex, "/") // just in case
			if hex == "" {
				continue
			}
			digest := godigest.SHA256.String() + ":" + hex
			ic.blobs[digest] = data
		}
	}

	// Parse index.json to find the manifest(s).
	indexData, ok := files[ocispec.ImageIndexFile]
	if !ok {
		return nil, fmt.Errorf("OCI layout missing %s", ocispec.ImageIndexFile)
	}

	var idx Index
	if err := json.Unmarshal(indexData, &idx); err != nil {
		return nil, fmt.Errorf("parse %s: %w", ocispec.ImageIndexFile, err)
	}

	if len(idx.Manifests) == 0 {
		return nil, fmt.Errorf("%s has no manifests", ocispec.ImageIndexFile)
	}

	// If there's a single manifest, use it directly. If there's an index,
	// we use the index itself as the manifest (it may be a manifest list).
	if len(idx.Manifests) == 1 {
		desc := idx.Manifests[0]
		ic.manifestDigest = desc.Digest

		// Check if the referenced manifest is itself an index (manifest list).
		if data, ok := ic.blobs[desc.Digest]; ok {
			var probe struct {
				MediaType string            `json:"mediaType"`
				Manifests []json.RawMessage `json:"manifests"`
			}
			if err := json.Unmarshal(data, &probe); err == nil && len(probe.Manifests) > 0 {
				// It's a manifest list/index. Pick the first concrete image
				// manifest (not an attestation).
				var innerIdx Index
				if err := json.Unmarshal(data, &innerIdx); err == nil {
					for _, m := range innerIdx.Manifests {
						if m.MediaType == ocispec.MediaTypeImageManifest ||
							m.MediaType == mediaTypeDockerManifest {
							ic.manifestDigest = m.Digest
							break
						}
					}
				}
			}
		}
	} else {
		// Multiple manifests in the index. Serialize the index itself as a blob
		// and use it as the manifest.
		indexDigest := digestBytes(indexData)
		ic.blobs[indexDigest] = indexData
		ic.manifestDigest = indexDigest
	}

	return ic, nil
}

// dockerManifestJSON is the structure of manifest.json in Docker format tars.
type dockerManifestJSON struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// extractDockerFormat handles tars in Docker's legacy format.
func (s *Store) extractDockerFormat(files map[string][]byte) (*imageContent, error) {
	ic := &imageContent{
		blobs: make(map[string][]byte),
	}

	manifestData, ok := files[dockerManifestFile]
	if !ok {
		return nil, fmt.Errorf("docker format tar missing %s", dockerManifestFile)
	}

	var dockerManifests []dockerManifestJSON
	if err := json.Unmarshal(manifestData, &dockerManifests); err != nil {
		return nil, fmt.Errorf("parse %s: %w", dockerManifestFile, err)
	}

	if len(dockerManifests) == 0 {
		return nil, fmt.Errorf("%s is empty", dockerManifestFile)
	}

	dm := dockerManifests[0]

	// Read and store the config blob.
	configData, ok := files[dm.Config]
	if !ok {
		return nil, fmt.Errorf("config not found in tar: %s", dm.Config)
	}
	configDigest := digestBytes(configData)
	ic.blobs[configDigest] = configData

	// Process each layer: read the uncompressed layer.tar, gzip compress it,
	// and compute the compressed digest.
	var layerDescs []Descriptor
	for _, layerPath := range dm.Layers {
		layerData, ok := files[layerPath]
		if !ok {
			return nil, fmt.Errorf("layer not found in tar: %s", layerPath)
		}

		// Gzip compress the layer.
		compressed, err := gzipCompress(layerData)
		if err != nil {
			return nil, fmt.Errorf("compress layer %s: %w", layerPath, err)
		}

		layerDigest := digestBytes(compressed)
		ic.blobs[layerDigest] = compressed

		layerDescs = append(layerDescs, Descriptor{
			MediaType: ocispec.MediaTypeImageLayerGzip,
			Digest:    layerDigest,
			Size:      int64(len(compressed)),
		})

		s.log.Debug("processed layer",
			"path", layerPath,
			"uncompressed", len(layerData),
			"compressed", len(compressed),
			"digest", layerDigest,
		)
	}

	// Build the OCI manifest.
	manifest := Manifest{
		SchemaVersion: ociSchemaVersion,
		MediaType:     ocispec.MediaTypeImageManifest,
		Config: Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configData)),
		},
		Layers: layerDescs,
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}

	manifestDigest := digestBytes(manifestBytes)
	ic.blobs[manifestDigest] = manifestBytes
	ic.manifestDigest = manifestDigest

	return ic, nil
}

// readTarFiles reads all files from a tar archive into a map of name -> contents.
func readTarFiles(r io.Reader) (map[string][]byte, error) {
	tr := tar.NewReader(r)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", hdr.Name, err)
		}
		files[hdr.Name] = data
	}
	return files, nil
}

// digestBytes computes "sha256:<hex>" for the given data.
func digestBytes(data []byte) string {
	return godigest.FromBytes(data).String()
}

// gzipCompress compresses data with gzip.
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// parseRepoTag parses a Docker-style "repo:tag" string using the OCI
// distribution reference spec. Returns (repository-path, tag, error).
func parseRepoTag(repoTag string) (string, string, error) {
	named, err := reference.ParseNormalizedNamed(repoTag)
	if err != nil {
		return "", "", err
	}
	tagged, ok := reference.TagNameOnly(named).(reference.Tagged)
	if !ok {
		return "", "", fmt.Errorf("not tagged: %s", repoTag)
	}
	return reference.Path(named), tagged.Tag(), nil
}
