package registry

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ndbaker1/regi/store"
)

const (
	headerAPIVersion    = "Docker-Distribution-API-Version"
	headerContentDigest = "Docker-Content-Digest"

	apiVersion = "registry/2.0"

	contentTypeJSON        = "application/json"
	contentTypeOctetStream = "application/octet-stream"

	// OCI Distribution Spec error codes.
	errCodeBlobUnknown     = "BLOB_UNKNOWN"
	errCodeManifestUnknown = "MANIFEST_UNKNOWN"
	errCodeNameUnknown     = "NAME_UNKNOWN"
	errCodeInternalError   = "INTERNAL_ERROR"

	// Route constants.
	pathV2       = "/v2/"
	pathCatalog  = "/v2/_catalog"
	sepManifests = "/manifests/"
	sepBlobs     = "/blobs/"
	suffixTags   = "/tags/list"
)

// Handler serves OCI Distribution v2 API requests.
type Handler struct {
	store *store.Store
	log   *slog.Logger
}

// New creates a registry handler backed by the given store.
func New(s *store.Store, log *slog.Logger) *Handler {
	return &Handler{store: s, log: log}
}

// ServeHTTP routes requests to the appropriate handler based on the path.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// All responses include the required API version header.
	w.Header().Set(headerAPIVersion, apiVersion)

	h.log.Debug("request", "method", r.Method, "path", path)

	switch path {
	case pathV2, "/v2":
		h.handleV2Check(w, r)

	case pathCatalog:
		h.handleCatalog(w, r)

	default:
		// ONLY v2 apis are supported.
		path, ok := strings.CutPrefix(path, "/v2/")
		if !ok {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "not found")
			return
		}
		// try to match known suffixes.
		if name, ref, ok := matchSuffix(path, sepManifests); ok {
			h.handleManifest(w, r, name, ref)
		} else if name, digest, ok := matchSuffix(path, sepBlobs); ok {
			h.handleBlob(w, r, name, digest)
		} else if name, ok := matchTagsList(path); ok {
			h.handleTagsList(w, r, name)
		} else {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "not found")
		}
	}
}

// handleV2Check implements GET /v2/ -- the version check endpoint.
func (h *Handler) handleV2Check(w http.ResponseWriter, r *http.Request) {
	h.log.Info("ping", "remote", r.RemoteAddr)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{}`))
}

// handleCatalog implements GET /v2/_catalog.
func (h *Handler) handleCatalog(w http.ResponseWriter, r *http.Request) {
	repos, err := h.store.Repositories(r.Context())
	if err != nil {
		h.log.Error("catalog", "error", err)
		h.writeError(w, http.StatusInternalServerError, errCodeInternalError, err.Error())
		return
	}
	if repos == nil {
		repos = []string{}
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"repositories": repos})
}

// handleTagsList implements GET /v2/{name}/tags/list.
func (h *Handler) handleTagsList(w http.ResponseWriter, r *http.Request, name string) {
	tags, err := h.store.Tags(r.Context(), name)
	if err != nil {
		if isNotFound(err) {
			h.writeError(w, http.StatusNotFound, errCodeNameUnknown, "repository name not known to registry: "+name)
			return
		}
		h.log.Error("tags list", "name", name, "error", err)
		h.writeError(w, http.StatusInternalServerError, errCodeInternalError, err.Error())
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"name": name, "tags": tags})
}

// handleManifest implements GET|HEAD /v2/{name}/manifests/{reference}.
func (h *Handler) handleManifest(w http.ResponseWriter, r *http.Request, name, reference string) {
	data, digest, mediaType, err := h.store.ResolveManifest(r.Context(), name, reference)
	if err != nil {
		if isNotFound(err) {
			h.writeError(w, http.StatusNotFound, errCodeManifestUnknown, err.Error())
			return
		}
		h.log.Error("manifest", "name", name, "ref", reference, "error", err)
		h.writeError(w, http.StatusInternalServerError, errCodeInternalError, err.Error())
		return
	}

	w.Header().Set("Content-Type", mediaType)
	w.Header().Set(headerContentDigest, digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleBlob implements GET|HEAD /v2/{name}/blobs/{digest}.
func (h *Handler) handleBlob(w http.ResponseWriter, r *http.Request, name, digest string) {
	h.log.Info("blob", "remote", r.RemoteAddr)
	if r.Method == http.MethodHead {
		size, ok := h.store.HasBlob(r.Context(), name, digest)
		if !ok {
			h.writeError(w, http.StatusNotFound, errCodeBlobUnknown, "blob unknown to registry: "+digest)
			return
		}
		w.Header().Set("Content-Type", contentTypeOctetStream)
		w.Header().Set(headerContentDigest, digest)
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}

	data, err := h.store.GetBlob(r.Context(), name, digest)
	if err != nil {
		if isNotFound(err) {
			h.writeError(w, http.StatusNotFound, errCodeBlobUnknown, "blob unknown to registry: "+digest)
			return
		}
		h.log.Error("blob", "name", name, "digest", digest, "error", err)
		h.writeError(w, http.StatusInternalServerError, errCodeInternalError, err.Error())
		return
	}

	w.Header().Set("Content-Type", contentTypeOctetStream)
	w.Header().Set(headerContentDigest, digest)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// isNotFound returns true if the error indicates a missing resource.
func isNotFound(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "No such image") ||
		strings.Contains(msg, "manifest unknown") ||
		strings.Contains(msg, "does not exist")
}

// ociError is the OCI Distribution Spec error format.
type ociError struct {
	Errors []ociErrorEntry `json:"errors"`
}

type ociErrorEntry struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	err := ociError{
		Errors: []ociErrorEntry{{Code: code, Message: message}},
	}
	h.log.Info("error response", "error", err)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(err)
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// matchSuffix attempts to split "some/name/manifests/ref" by the given sep
// ("/manifests/" or "/blobs/"). Returns (name, rest, true) if the sep is found.
// The name portion can contain slashes.
func matchSuffix(path, sep string) (string, string, bool) {
	idx := strings.LastIndex(path, sep)
	if idx < 0 {
		return "", "", false
	}
	name := path[:idx]
	rest := path[idx+len(sep):]
	if name == "" || rest == "" {
		return "", "", false
	}
	return name, rest, true
}

// matchTagsList checks if path matches "{name}/tags/list".
func matchTagsList(path string) (string, bool) {
	if !strings.HasSuffix(path, suffixTags) {
		return "", false
	}
	name := path[:len(path)-len(suffixTags)]
	if name == "" {
		return "", false
	}
	return name, true
}
