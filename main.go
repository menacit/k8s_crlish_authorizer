package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"net/http"
	"os"

	k8sAuthorizationV1 "k8s.io/api/authorization/v1"
)

var listenAddress, certificatePath, privateKeyPath, deniedCredentialIDsPath string
var deniedCredentialIDs []string

var verboseLogging bool
var legacyLogger *log.Logger
var logger *slog.Logger

// ---
func init() {
	flag.StringVar(
		&listenAddress, "listen-address", ":8443", "Address and port mapping for HTTPS server")

	flag.StringVar(
		&certificatePath, "certificate", "/etc/k8s_crlish_authorizer/x509/tls.crt",
		"Path to X.509 certificate in PEM format for HTTPS server")

	flag.StringVar(
		&privateKeyPath, "key", "/etc/k8s_crlish_authorizer/x509/tls.key",
		"Path to private key in PEM format for HTTPS server")

	flag.StringVar(
		&deniedCredentialIDsPath, "deny", "/etc/k8s_crlish_authorizer/conf/credential_ids.json",
		"Path to JSON formatted file containing a list of credential IDs which should be denied")

	flag.BoolVar(&verboseLogging, "verbose", false, "Enable verbose debug logging")

	var logLevel slog.Level
	if verboseLogging {
		logLevel = slog.LevelDebug

	} else {
		logLevel = slog.LevelInfo
	}

	logHandler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})
	logger = slog.New(logHandler)
	logger.Debug("Finished reading static configuration from arguments")

	legacyLogger = slog.NewLogLogger(logHandler, slog.LevelError)

	logger.Debug(
		"Reading JSON file with list of credential IDs which should be denied",
		slog.String("file_path", deniedCredentialIDsPath))

	rawDeniedCredentialIDs, err := ioutil.ReadFile(deniedCredentialIDsPath)
	if err != nil {
		logger.Error(
			"Failed to read file with denied credential IDs",
			slog.String("file_path", deniedCredentialIDsPath),
			slog.String("error_reason", err.Error()))

		os.Exit(1)
	}

	logger.Debug("Parsing data from denied credential IDs file as JSON")
	err = json.Unmarshal(rawDeniedCredentialIDs, &deniedCredentialIDs)
	if err != nil {
		logger.Error(
			"Failed to parse file containg denied credential IDs as JSON",
			slog.String("file_path", deniedCredentialIDsPath),
			slog.String("error_reason", err.Error()))

		os.Exit(1)
	}
}

// ---
func healthHandler(response http.ResponseWriter, request *http.Request) {
	logger.Debug("Handling request to health check endpoint")

	response.Header().Set("Content-Type", "text/plain")
	response.Write([]byte("OK"))
	return
}

// ---
func authorizationHandler(response http.ResponseWriter, request *http.Request) {
	logger.Debug(
		"Handling authorization request", slog.String("remote-address", request.RemoteAddr))

	if request.Method != "POST" {
		logger.Debug("Recieved authorization request without POST as HTTP method")
		http.Error(response, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Debug("Reading data from request body")

	defer request.Body.Close()
	rawSubjectAccessReview, err := ioutil.ReadAll(request.Body)
	if err != nil {
		logger.Warn(
			"Failed to read body of authorization request",
			slog.String("error_reason", err.Error()))

		http.Error(response, "Failed to read submitted body", http.StatusBadRequest)
		return
	}

	logger.Debug("Parsing request body data as SubjectAccessReview JSON")

	var subjectAccessReview k8sAuthorizationV1.SubjectAccessReview
	err = json.Unmarshal(rawSubjectAccessReview, &subjectAccessReview)
	if err != nil {
		logger.Warn(
			"Failed to parse submitted request data as SubjectAccessReview JSON",
			slog.String("error_reason", err.Error()))

		http.Error(response, "Failed to parse submitted body", http.StatusBadRequest)
		return
	}

	response.Header().Set("Content-Type", "application/json")
	subjectAccessReview.Status.Allowed = false
	subjectAccessReview.Status.Denied = false

	logger.Debug("Checking if access review user has a credential ID specified")
	credentialIDs, keyExist := subjectAccessReview.Spec.Extra[
		"authentication.kubernetes.io/credential-id"]

	if !keyExist || len(credentialIDs) == 0 {
		logger.Debug("Access review data doesn't contain credential ID")

		subjectAccessReview.Status.Reason = "Access review data doesn't contain credential ID"
		responseData, _ := json.Marshal(subjectAccessReview)
		response.Write(responseData)
		return
	}

	logger.Debug("Checking if credential IDs in access review data are in the deny list")

	subjectAccessReview.Status.Reason = "Credential ID is not included in deny list (\"CRLish\")"

	// While "Extras" field is always a list of strings, I don't see why multiple credential IDs
	// could be provided by the authenticator
	for _, credentialID := range credentialIDs {
		logger.Debug(
			"Checking if specific credential ID is included in deny list",
			slog.String("credential-id", credentialID))

		for _, deniedCredentialID := range deniedCredentialIDs {
			if credentialID == deniedCredentialID {
				logger.Warn(
					"Subject access review data contains credential ID included in deny list",
					slog.String("credential-id", credentialID))

				subjectAccessReview.Status.Denied = true
				subjectAccessReview.Status.Reason = fmt.Sprintf(
					"Credential ID \"%s\" is included in deny list (\"CRLish\")", credentialID)

				break
			}
		}
	}

	logger.Debug("Returning access review response data")
	responseData, _ := json.Marshal(subjectAccessReview)
	response.Write(responseData)
}

// ---
func main() {
	logger.Info(
		"Starting crlish authorizer HTTPS server",
		slog.String("listen-address", listenAddress))

	http.HandleFunc("/healthz", healthHandler)
	http.HandleFunc("/", authorizationHandler)

	server := http.Server{
		Addr:     listenAddress,
		ErrorLog: legacyLogger,
	}

	err := server.ListenAndServeTLS(certificatePath, privateKeyPath)
	if err != nil {
		logger.Error(
			"Unrecoverable error occured in HTTPS server",
			slog.String("error_reason", err.Error()))

		os.Exit(1)
	}
}
