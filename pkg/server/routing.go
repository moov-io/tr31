package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/moov-io/base"
	moovhttp "github.com/moov-io/base/http"
)

var (
	bugReportHelp = "please report this as a bug -- https://github.com/moov-io/tr31/issues/new"

	// ErrBadRouting is returned when an expected path variable is missing, which is always programmer error.
	ErrBadRouting = fmt.Errorf("inconsistent mapping between route and handler, %s", bugReportHelp)
	ErrFoundABug  = fmt.Errorf("snuck into machine with err == nil, %s", bugReportHelp)

	errInvalidMachine = errors.New("invalid tr31 machine")

	errInvalidVaultAddress = errors.New("Invalid Vault Address.")
	errInvalidVaultToken   = errors.New("Invalid vault Token.")
	errInvalidRequestId    = errors.New("Invalid Request ID.")
	errInvalidKeyPath      = errors.New("Invalid Key Path.")
	errInvalidKeyName      = errors.New("Invalid Key Name.")
	errInvalidKeyBlock     = errors.New("Invalid Key Block.")
)

// contextKey is a unique (and compariable) type we use
// to store and retrieve additional information in the
// go-kit context.
var contextKey struct{}

// saveCORSHeadersIntoContext saves CORS headers into the go-kit context.
//
// This is designed to be added as a ServerOption in our main http handler.
func saveCORSHeadersIntoContext() httptransport.RequestFunc {
	return func(ctx context.Context, r *http.Request) context.Context {
		origin := r.Header.Get("Origin")
		return context.WithValue(ctx, contextKey, origin)
	}
}

// respondWithSavedCORSHeaders looks in the go-kit request context
// for our own CORS headers. (Stored with our context key in
// saveCORSHeadersIntoContext.)
//
// This is designed to be added as a ServerOption in our main http handler.
func respondWithSavedCORSHeaders() httptransport.ServerResponseFunc {
	return func(ctx context.Context, w http.ResponseWriter) context.Context {
		v, ok := ctx.Value(contextKey).(string)
		if ok && v != "" {
			moovhttp.SetAccessControlAllowHeaders(w, v) // set CORS headers
		}
		return ctx
	}
}

// preflightHandler captures Corss Origin Resource Sharing (CORS) requests
// by looking at all OPTIONS requests for the Origin header, parsing that
// and responding back with the other Access-Control-Allow-* headers.
//
// Docs: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
func preflightHandler(options []httptransport.ServerOption) http.Handler {
	return httptransport.NewServer(
		endpoint.Nop,
		httptransport.NopRequestDecoder,
		func(_ context.Context, w http.ResponseWriter, _ interface{}) error {
			if v := w.Header().Get("Content-Type"); v == "" {
				w.Header().Set("Content-Type", "text/plain")
			}
			return nil
		},
		options...,
	)
}

func MakeHTTPHandler(s Service) http.Handler {
	r := mux.NewRouter()
	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(encodeError),
		httptransport.ServerBefore(saveCORSHeadersIntoContext()),
		httptransport.ServerAfter(respondWithSavedCORSHeaders()),
	}

	// HTTP Methods
	r.Methods("OPTIONS").Handler(preflightHandler(options)) // CORS pre-flight handler
	r.Methods("GET").Path("/ping").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		moovhttp.SetAccessControlAllowHeaders(w, r.Header.Get("Origin"))
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("PONG"))
	})

	// REST APIs
	r.Methods("GET").Path("/machines").Handler(httptransport.NewServer(
		getMachinesEndpoint(s),
		decodeGetMachinesRequest,
		encodeResponse,
		options...,
	))

	r.Methods("GET").Path("/machine/{ik}").Handler(httptransport.NewServer(
		findMachineEndpoint(s),
		decodeFindMachineRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/machine").Handler(httptransport.NewServer(
		createMachineEndpoint(s),
		decodeCreateMachineRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/encrypt_data").Handler(httptransport.NewServer(
		encryptDataEndpoint(s),
		decodeEncryptDataRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/decrypt_data").Handler(httptransport.NewServer(
		decryptDataEndpoint(s),
		decodeDecryptDataRequest,
		encodeResponse,
		options...,
	))

	return r
}

// errorer is implemented by all concrete response types that may contain
// errors. There are a few well-known values which are used to change the
// HTTP response code without needing to trigger an endpoint (transport-level)
// error.
type errorer interface {
	error() error
}

// counter is implemented by any concrete response types that may contain
// some arbitrary count information.
type counter interface {
	count() int
}

// marshalStructWithError converts a struct into a JSON response with all fields of the struct
// with our expected error formats.
//
// There are a few reasons we need to do this.
//  1. base.ErrorList marshals to an object which breaks the string format our API declares
//     and isn't caught when we pass around interface{} values.
//  2. We want to return additional fields of structs (such as in createFileEndpoint)
func marshalStructWithError(in interface{}, w http.ResponseWriter) error {
	v := reflect.ValueOf(in)
	out := make(map[string]interface{}, v.NumField())

	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		value := v.Field(i).Interface()

		if err, ok := value.(error); ok {
			out["error"] = err.Error()
		} else {
			out[name] = value
		}
	}

	return json.NewEncoder(w).Encode(out)
}

// encodeResponse is the common method to encode all response types to the
// client. I chose to do it this way because, since we're using JSON, there's no
// reason to provide anything more specific. It's certainly possible to
// specialize on a per-response (per-method) basis.
func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	if e, ok := response.(errorer); ok && e.error() != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(codeFrom(e.error()))
		return marshalStructWithError(response, w)
	}

	// Used for pagination
	if e, ok := response.(counter); ok {
		w.Header().Set("X-Total-Count", strconv.Itoa(e.count()))
	}

	if v := w.Header().Get("Content-Type"); v == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Only write json body if we're setting response as json
		return json.NewEncoder(w).Encode(response)
	}
	return nil
}

// encodeError JSON encodes the supplied error
func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		err = ErrFoundABug
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(codeFrom(err))
	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
	if err != nil {
		w.Write([]byte(fmt.Sprintf("problem rendering json: %v", err)))
	}
}

func codeFrom(err error) int {
	if err == nil {
		return http.StatusOK
	}

	errString := fmt.Sprintf("%#v", err)
	if el, ok := err.(base.ErrorList); ok {
		errString = el.Error()
	}
	switch {
	case
		strings.Contains(errString, errInvalidMachine.Error()):
		return http.StatusBadRequest
	}

	switch err {
	case ErrNotFound:
		return http.StatusNotFound
	case ErrAlreadyExists:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
