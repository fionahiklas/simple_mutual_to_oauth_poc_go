package main

import (
    "github.com/gorilla/mux"
    "github.com/bestmethod/logger"

    "net/http"
    "net/url"
    "context"

    "crypto/x509"
    "crypto/tls"

    "io/ioutil"
    "os"
    "time"
    "strconv"

    "golang.org/x/oauth2"
    "golang.org/x/oauth2/clientcredentials"

    "github.com/dgryski/dgoogauth"
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
  TokenURL string // Used for getting a token from the downstream server
  PostURL string   // URL to proxy requests to
  ClientID string // ID for this client
  ClientSecret string // Secret value used in authentication
}

var log *Logger.Logger

/*
  Create code from Client Secret string for use with the stub we're testing against
  TODO: Remove when using this code for real :)
*/
func CalculateClientSecretCode(clientSecretString string) string {
  currentUnixTime := time.Now().Unix()
  calculatedCode := dgoogauth.ComputeCode(clientSecretString, currentUnixTime)
  log.Debug("Calculated client secret code: %d", calculatedCode)
  return strconv.Itoa(calculatedCode)
}

/*
  For any HTTP request map the client certificate details to
  an OAuth token and pass on the request/return the response
  from the downstream service.
*/
func BuildHttpRequestHander(listenerConfig *MutualAuthListenerConfig) func(http.ResponseWriter, *http.Request) {

  return func(response http.ResponseWriter, request *http.Request) {
    log.Debug("Got request: %s", request)

    log.Debug("REQUEST: Method: %s", request.Method)
    log.Debug("REQUEST: URL: %s", request.URL)

    connectionState := request.TLS
    certificates := connectionState.PeerCertificates
    log.Debug("REQUEST: TLS: Peer certs count: %d", len(certificates))
    for _, certificate := range certificates {
      log.Debug("REQUEST: TLS: Signature: %s", []byte(certificate.Signature))
      log.Debug("REQUEST: TLS: Subject: %s", certificate.Subject)
      log.Debug("REQUEST: TLS: Subject: %s", certificate.IsCA)
    }

    // OAuth2 Config - need to recreate this for each client
    clientCredentialConfig := &clientcredentials.Config {
      TokenURL: listenerConfig.TokenURL,
      ClientID: listenerConfig.ClientID,
      ClientSecret: CalculateClientSecretCode(listenerConfig.ClientSecret),
      AuthStyle: oauth2.AuthStyleInParams,
    }

    log.Debug("Creating HTTP Client for OAuth2, using config: %s", clientCredentialConfig)
    httpClient := clientCredentialConfig.Client(context.Background())

    log.Debug("Calling client ...")
    queryParams := make(url.Values)
    clientResponse, clientError := httpClient.PostForm(listenerConfig.PostURL, queryParams)
    if clientError != nil {
      log.Debug("Got an error calling client: %s", clientError)
    } else {
      log.Debug("Client response status code: %d", clientResponse.StatusCode)
      log.Debug("Client response status: %s", clientResponse.Status)
    }
    response.Write([]byte("Hello, I heard you :)"))
  }
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
  listenerConfig.TokenURL = argsWithoutProg[4]
  listenerConfig.PostURL = argsWithoutProg[5]
  listenerConfig.ClientID = argsWithoutProg[6]
  listenerConfig.ClientSecret = argsWithoutProg[7]


  // Create the handler for HTTP(S) connections
  router := mux.NewRouter()
  handler := BuildHttpRequestHander(listenerConfig)

  router.HandleFunc("/hb", handler).Methods("GET")
  router.HandleFunc("/hb", handler).Methods("POST")

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
    Handler: router,
  }

	// listen using the server certificate which is validated by the client
  server.ListenAndServeTLS(listenerConfig.CertFile, listenerConfig.KeyFile)
  log.Debug("Got to end of code")
}
