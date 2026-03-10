package middleware

import "net/http"

// StatusRecorder wraps http.ResponseWriter to capture the response status code.
// It implements Unwrap() so that http.ResponseController (used by httputil.ReverseProxy)
// can reach the underlying writer's http.Flusher and http.Hijacker implementations.
type StatusRecorder struct {
	http.ResponseWriter
	StatusCode int
}

func NewStatusRecorder(w http.ResponseWriter) *StatusRecorder {
	return &StatusRecorder{ResponseWriter: w, StatusCode: http.StatusOK}
}

func (r *StatusRecorder) WriteHeader(code int) {
	r.StatusCode = code
	r.ResponseWriter.WriteHeader(code)
}

// Unwrap returns the underlying ResponseWriter so that http.ResponseController
// can access optional interfaces (http.Flusher, http.Hijacker) on the real writer.
func (r *StatusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
