package main

import (
    "github.com/gorilla/mux"
    "github.com/bestmethod/logger"
    "net/http"
    "crypto/x509"
    "crypto/tls"
    "io/ioutil"
    "os"
)

/*
  Contains all the data needed to construct an endpoint that
  accepts connections and translates these to OAuth-authorised
  calls to a downstream service
*/
type MutualAuthListenerConfig struct {
  Address string  // Of the form <address>:<port>
  KeyFile string  // The private key for the server
  CertFile string // The certificate for the server
  CAFile string   // The Certification Authority (chain of trust)
}

var log *Logger.Logger

/*
  For any HTTP request map the client certificate details to
  an OAuth token and pass on the request/return the response
  from the downstream service.
*/
func HttpRequestHandler(response http.ResponseWriter, request *http.Request) {
  log.Debug("Got request: %s", request)
  response.Write([]byte("Hello, I heard you :)"))
}


/*
  Basic setup for the application
*/
func init() {
  log = new(Logger.Logger)
  log.Init("[Main]", "MutualToOAuth",
    Logger.LEVEL_DEBUG | Logger.LEVEL_INFO |
    Logger.LEVEL_WARN, Logger.LEVEL_ERROR |
    Logger.LEVEL_CRITICAL, Logger.LEVEL_NONE)
}


/*
  MAIN FUNCTION
*/
func main() {
  argsWithoutProg := os.Args[1:]

  log.Debug("Command line arguments: %s", argsWithoutProg)

  listenerConfig := &MutualAuthListenerConfig{}

  listenerConfig.Address = argsWithoutProg[0]
  listenerConfig.KeyFile = argsWithoutProg[1]
  listenerConfig.CertFile = argsWithoutProg[2]
  listenerConfig.CAFile = argsWithoutProg[3]

  // Create the handler for HTTP(S) connections
  router := mux.NewRouter()
  router.HandleFunc("/hb", HttpRequestHandler).Methods("GET")
  router.HandleFunc("/hb", HttpRequestHandler).Methods("POST")

  log.Debug("Attempting to read CA cert from: %s",listenerConfig.CAFile)

	caCert, err := ioutil.ReadFile(listenerConfig.CAFile)
	if err != nil {
    log.Fatalf(1, "Error reading CA file '%s' message: %s", listenerConfig.CAFile)
	}

  log.Debug("Creating CA cert pool")
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

  log.Debug("Creating TLS config")
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,                     // used to verify the client cert is signed by the CA and is therefore valid
		ClientAuth: tls.RequireAndVerifyClientCert, // this requires a valid client certificate to be supplied during handshake
	}

  log.Debug("Creating server for ")
	server := &http.Server{
		Addr:      listenerConfig.Address,
		TLSConfig: tlsConfig,
    Handler: router }

	// listen using the server certificate which is validated by the client
  server.ListenAndServeTLS(listenerConfig.CertFile, listenerConfig.KeyFile)
  log.Debug("Got to end of code")
}
