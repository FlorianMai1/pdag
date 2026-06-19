package sdk

import (
	"bytes"
	"io"
	"net/http"
	"net/url"

	pb "github.com/FlorianMai1/pdag/proto/authz"
)

// HttpRequestToStdlib converts a protobuf HttpRequest back to a standard *http.Request.
// This is a convenience for plugin authors who prefer working with the stdlib type.
func HttpRequestToStdlib(req *pb.HttpRequest) *http.Request {
	u := &url.URL{
		Scheme:   req.Scheme,
		Host:     req.Host,
		Path:     req.Path,
		RawQuery: req.RawQuery,
	}

	header := make(http.Header, len(req.Headers))
	for _, h := range req.Headers {
		header[h.Key] = h.Values
	}

	var body io.ReadCloser
	if len(req.Body) > 0 {
		body = io.NopCloser(bytes.NewReader(req.Body))
	} else {
		body = http.NoBody
	}

	return &http.Request{
		Method:        req.Method,
		URL:           u,
		Host:          req.Host,
		Header:        header,
		Body:          body,
		ContentLength: req.ContentLength,
		RemoteAddr:    req.RemoteAddr,
	}
}

// StdlibToHttpRequest converts an *http.Request plus buffered body to a protobuf HttpRequest.
// Used by PDAG core when calling plugins.
func StdlibToHttpRequest(r *http.Request, body []byte, requestID, principal string) *pb.HttpRequest {
	headers := make([]*pb.Header, 0, len(r.Header))
	for k, v := range r.Header {
		headers = append(headers, &pb.Header{Key: k, Values: v})
	}

	return &pb.HttpRequest{
		Method:        r.Method,
		Scheme:        r.URL.Scheme,
		Host:          r.Host,
		Path:          r.URL.Path,
		RawQuery:      r.URL.RawQuery,
		Headers:       headers,
		Body:          body,
		ContentLength: r.ContentLength,
		RemoteAddr:    r.RemoteAddr,
		RequestId:     requestID,
		Principal:     principal,
	}
}
