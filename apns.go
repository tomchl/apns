package apns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/martindrlik/org/confirm"
	"golang.org/x/crypto/pkcs12"
)

func iosHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	dec := json.NewDecoder(r.Body)

	var notification notification
	err := dec.Decode(&notification)
	if err != nil {
		panic(err)
	}
	log.Println("AppId from body: ", notification.ApplicationID)
	log.Println("Host: ", notification.BaseURL)
	log.Println("NotifToken: ", notification.NotificationToken)

	confirmrequest := confirmrequest{notification.ApplicationID, notification.NotificationToken, "Ios"}

	confirm.Channel <- confirm.Payload{
		ApplicationId: confirmrequest.ApplicationID,
		BaseURL:       notification.BaseURL,
		Platform:      confirmrequest.Platform,
		Token:         confirmrequest.NotificationToken}
}

type notification struct {
	NotificationToken string
	BaseURL           string
	ApplicationID     uint64
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

// ListenAndServeTLS always returns a non-nil error. After Shutdown or
// Close, the returned error is ErrServerClosed.
func ListenAndServeTLS(addr, certFile, keyFile, appleCert, password string) {
	flag.Parse()
	fmt.Println("Server is listening http2 on port " + addr)

	mux := &http.ServeMux{}
	mux.HandleFunc("/3/device/", iosHandler)

	pool := x509.NewCertPool()
	pool.AddCert(mustDecodeCert(appleCert, password))

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  pool,
		},
		ErrorLog: log.New(ioutil.Discard, "", 0),
	}
	defer fmt.Println("Ended...")
	return server.ListenAndServeTLS(certFile, keyFile)
}

/*
{
    "apiKey": "xxx",
    "applicationId": 103004,

    "Notifications": [
        {
            "ClientIds": [
                "xxx"
            ],
            "Title": "Test title",
            "Message": "Test text",
            "Content": {
                "ApplicationID": 103004,
                "BaseURL": "http://tch.inspirecloud.local.net:8580"
            }
        }
    ]
}
>> {"ApplicationID":103004,"BaseHostURL":"http://tch.inspirecloud.local.net:8580","eventId":8958,"notificationToken":"6b25238c-f536-4f85-9099-c4ae982af8ec8958","checksum":2940516379,"aps":{"alert":{"title":"Test title","body":"Test text"}}}
*/
