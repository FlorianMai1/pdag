package middleware

import "net/http"

// StatusRecorder wraps http.ResponseWriter to capture the response status code.
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
