package main

import (
  "flag"
  "github.com/bestmethod/logger"
  "github.com/gorilla/mux"
  "io"
  "net/url"

  //"net/url"

  "context"
  "crypto/tls"
  "crypto/x509"
  "net/http"

  "golang.org/x/oauth2"
  "golang.org/x/oauth2/clientcredentials"
  "io/ioutil"
)


const READ_WRITE_BUFFER_SIZE = 20

/*
  Contains all the data needed to construct an endpoint that
  accepts connections and translates these to OAuth-authorised
  calls to a downstream service
*/
type MutualAuthListenerConfig struct {
  Address        string // Of the form <address>:<port>
  KeyFile        string // The private key for the server
  CertFile       string // The certificate for the server
  CAFile         string // The Certification Authority (chain of trust)
  TokenURL       string // Used for getting a token from the downstream server
  ApplicationURL string // URL to proxy requests to
  ApplicationHost string // Host header for the client
  ClientID       string // ID for this client
  ClientSecret   string // Secret value used in authentication
}

var log *Logger.Logger

type LoggingTransport struct {
  DownstreamTransport http.RoundTripper
}

func (loggingTransport *LoggingTransport) RoundTrip(requestToLog *http.Request) (*http.Response, error) {
  log.Debug("LOG HTTP: Request: %s", requestToLog)
  log.Debug("LOG HTTP: Headers: %s", requestToLog.Header)
  log.Debug("LOG HTTP: Auth Head: %s", requestToLog.Header.Get("Authorization"))

  responseToLog, errorToLog := loggingTransport.DownstreamTransport.RoundTrip(requestToLog)
  log.Debug("LOG HTTP: Response: %s, error: %s", responseToLog, errorToLog)
  return responseToLog, errorToLog
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
      log.Debug("REQUEST: TLS: Subject: %s", certificate.Subject)
    }

    // OAuth2 Config - need to recreate this for each client
    clientCredentialConfig := &clientcredentials.Config {
      TokenURL: listenerConfig.TokenURL,
      ClientID: listenerConfig.ClientID,
      ClientSecret: listenerConfig.ClientSecret,
      // TODO: THis is currently broken as Kong seems to have used "email,phone,address" as one scope
      // TODO: rather than creating a list of 3 different scopes
      Scopes: []string{ "email,phone,address" },
      AuthStyle: oauth2.AuthStyleInHeader,
    }

    log.Debug("Creating HTTP Client for OAuth2, using config: %s", clientCredentialConfig)

    // TODO: Hack to ignore SSL cert of the server
    transportThatIgnoresSSL := &http.Transport{
      TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }

    httpClientToIgnoreSSL := &http.Client{
      Transport: transportThatIgnoresSSL,
    }

    currentTransport := httpClientToIgnoreSSL.Transport
    loggingTransport := &LoggingTransport{
      DownstreamTransport: currentTransport,
    }

    // TODO: I think this could be refactored
    httpClientToIgnoreSSL.Transport = loggingTransport

    contextForOAuthClient := context.WithValue(context.Background(), oauth2.HTTPClient, httpClientToIgnoreSSL)

    httpClient := clientCredentialConfig.Client(contextForOAuthClient)

    log.Debug("HTTP Client transport: %s", httpClient.Transport)

    log.Debug("Creating request")
    clientUrl, urlError := url.Parse(listenerConfig.ApplicationURL)
    if urlError != nil {
      log.Error("Error parsing URL: %s", urlError)
      return
    }

    clientRequest := &http.Request{
      Method: "GET",
      URL: clientUrl,
      Host: listenerConfig.ApplicationHost,
    }

    log.Debug("Calling client with request: %s", clientRequest)

    clientResponse, clientError := httpClient.Do(clientRequest)

    if clientError != nil {
      log.Debug("Got an error calling client: %s", clientError)
      response.WriteHeader(500)
      return
    }

    log.Debug("Client response status code: %d", clientResponse.StatusCode)
    log.Debug("Client response status: %s", clientResponse.Status)

    // Clean up the HTTP client call at the end of this function
    defer clientResponse.Body.Close()

    response.Write([]byte("Got this response from downstream:\n"))

    log.Debug("Reading downstream response and copying to reply")
    buffer := make([]byte, READ_WRITE_BUFFER_SIZE)
    for {
      bytesRead, readError := clientResponse.Body.Read(buffer)
      log.Debug("Read %d bytes from downstream", bytesRead)
      if bytesRead > 0 {
        log.Debug("Writing %d bytes", bytesRead)
        response.Write(buffer[:bytesRead])
      }
      if readError == io.EOF {
        log.Debug("Reached EOF from downstream")
        break
      }
    }
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

  // Holds all of the config values
  listenerConfig := &MutualAuthListenerConfig{}
  helpFlag := false

  flag.StringVar(&listenerConfig.Address, "listenAddr", "127.0.0.1:8443", "The address to listen for connections on")
  flag.StringVar(&listenerConfig.KeyFile, "keyFile", "", "Private key for TLS for listening endpoint")
  flag.StringVar(&listenerConfig.CertFile, "certFile", "", "Certificate file for TLD listening endpoint")
  flag.StringVar(&listenerConfig.CAFile, "caFile", "", "Certification authority file")
  flag.StringVar(&listenerConfig.TokenURL, "tokenURL", "", "OAuth2 Token URL")
  flag.StringVar(&listenerConfig.ApplicationURL, "applicationURL", "", "URL to access the service")
  flag.StringVar(&listenerConfig.ApplicationHost, "applicationHost", "", "Host header to pass downstream")
  flag.StringVar(&listenerConfig.ClientID, "clientID", "", "Unique ID for this client for OAuth authentication")
  flag.StringVar(&listenerConfig.ClientSecret, "clientSecret", "", "The client secret for authentication")
  flag.BoolVar(&helpFlag, "help", false, "Display help")
  flag.Parse()

  if helpFlag {
    flag.Usage()
    return
  }

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
