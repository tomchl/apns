package apns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/martindrlik/org/confirm"
	"github.com/martindrlik/org/notquery"
	"github.com/tomchl/logfilter"
	"golang.org/x/crypto/pkcs12"
)

const sendHandlerPattern = "/3/device/"

func iosHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Print(err)
		return
	}
	deviceToken := r.URL.Path[len(sendHandlerPattern):]

	expirationHeader := r.Header.Get("apns-expiration")
	expirationHeaderWithValue := []byte("{apns-expiration:" + expirationHeader + "}")
	notquery.Add(deviceToken, append(body, expirationHeaderWithValue...))
	var notification notification
	if err := json.Unmarshal(body, &notification); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		log.Print(err)
		return
	}

	log.Println("AppId from body: ", notification.ApplicationID)
	log.Println("Host: ", notification.BaseURL)
	log.Println("NotifToken: ", notification.NotificationToken)

	confirmrequest := confirmrequest{notification.ApplicationID, notification.NotificationToken, "Ios"}

	if isSuccessCode(notification.ResponseCode) &&
		notification.ResponseError == "" {
		confirmDeliveryPayloads <- confirm.Payload{
			ApplicationID: confirmrequest.ApplicationID,
			BaseURL:       notification.BaseURL,
			Platform:      confirmrequest.Platform,
			Token:         confirmrequest.NotificationToken}
	}
	if notification.ResponseCode != 0 {
		log.Println("ResponseCode: ", notification.ResponseCode)
		w.WriteHeader(notification.ResponseCode)
	}
	if notification.ResponseError != "" {
		log.Println("ResponseError: ", notification.ResponseError)
		enc := json.NewEncoder(w)
		if err := enc.Encode(response{
			Reason: notification.ResponseError}); err != nil {
			log.Fatal(err)
		}
	}
}

func isSuccessCode(i int) bool {
	return i == 0 || i >= 200 && i <= 300
}

type notification struct {
	NotificationToken string
	BaseURL           string
	ApplicationID     uint64
	ResponseCode      int
	ResponseError     string
}

type confirmrequest struct {
	ApplicationID     uint64
	NotificationToken string
	Platform          string
}

func mustDecodeCert(_name, password string) *x509.Certificate {
	bytes, err := ioutil.ReadFile(_name)
	if err != nil {
		log.Fatal(err)
	}

	_, cert, err := pkcs12.Decode(bytes, password)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

var confirmDeliveryPayloads = make(chan confirm.Payload, 2_000_000)

// ListenAndServeTLS always returns a non-nil error. After Shutdown or
// Close, the returned error is ErrServerClosed.
func ListenAndServeTLS(addr, certFile, keyFile, appleCert, password string) error {
	flag.Parse()
	mux := &http.ServeMux{}
	mux.HandleFunc(sendHandlerPattern, iosHandler)

	pool := x509.NewCertPool()
	pool.AddCert(mustDecodeCert(appleCert, password))

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		},
		ErrorLog: log.New(&logfilter.IgnoreHTTPWriter{}, "", 0),
	}
	confirm.Init(50, confirmDeliveryPayloads)
	return server.ListenAndServeTLS(certFile, keyFile)
}

type response struct {
	Reason string
}
