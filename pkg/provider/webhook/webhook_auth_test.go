package webhook

import (
	"context"
	b64 "encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	//"github.com/Azure/go-ntlmssp"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	"github.com/vadimi/go-http-ntlm/v2"
	"github.com/vadimi/go-ntlm/ntlm"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockAuthPackage struct {
	Request   mockAuthRequest
	Handler   mockAuthHandler
	TestCases []mockAuthTestCase
}

type mockAuthRequest func(url string, testCase mockAuthTestCase, t *testing.T) string
type mockAuthHandler func(secret string, validCreds creds, session ntlm.ServerSession, t *testing.T) http.HandlerFunc
type mockAuthTestCase struct {
	Creds    creds
	Expected string
}

type creds struct {
	UserName string
	Password string
}

func TestWebhookAuth(t *testing.T) {

	// testing data
	validCreds := creds{"correctuser123", "correctpassword123"}
	invalidCreds := creds{"incorrectuser123", "incorrectpassword123"}
	secret := "secret123"

	// define test cases
	authTestCases := []mockAuthTestCase{
		{validCreds, secret},
		{invalidCreds, "401"},
	}

	// define auth packages
	mockAuthPackages := map[string]mockAuthPackage{
		"BasicAuth": {basicAuthRequest, basicAuthHandler, authTestCases},
		"NTLM":      {ntlmAuthRequest, ntlmAuthHandler, authTestCases},
	}

	//create session which acts as DC
	session, _ := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
	session.SetUserInfo(validCreds.UserName, validCreds.Password, "")

	// start test server with mux
	mux := http.NewServeMux()
	for name, mockAuthPackage := range mockAuthPackages {
		endpoint := "/" + name
		mux.HandleFunc(endpoint, mockAuthPackage.Handler(secret, validCreds, session, t))
	}
	authTestServer := httptest.NewServer(mux)
	defer authTestServer.Close()

	// execute tests
	for name, mockAuthPackage := range mockAuthPackages {
		url := authTestServer.URL + "/" + name
		for _, mockAuthTestCase := range mockAuthPackage.TestCases {
			result := mockAuthPackage.Request(url, mockAuthTestCase, t)
			expected := mockAuthTestCase.Expected
			if result != expected {
				t.Errorf("got %q, expected %q", result, expected)
			}

		}
	}
}

func basicAuthHandler(secret string, validCreds creds, session ntlm.ServerSession, t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validCredsString := b64.StdEncoding.EncodeToString([]byte(validCreds.UserName + ":" + validCreds.Password))
		receivedCredsString := r.Header.Get("Authorization")

		if receivedCredsString == "" {
			w.Write([]byte("No Authorization header"))
			return
		}
		if receivedCredsString == validCredsString {
			w.Write([]byte(secret))
			return
		} else {
			w.Write([]byte("401"))
			return
		}
	}
}

func ntlmAuthHandler(secret string, validCreds creds, session ntlm.ServerSession, t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		/* create session which acts as DC
		session, _ := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
		session.SetUserInfo(validCreds.UserName, validCreds.Password, "")*/
		/*
			for name, _ := range r.Header {
				t.Log(name)

			}*/

		receivedCredsString := r.Header.Get("Authorization")
		//	t.Log(receivedCredsString)

		if receivedCredsString == "" {
			w.Write([]byte("No Authorization header"))
			return
		}
		ntlmChallengeString := strings.Replace(receivedCredsString, "NTLM ", "", -1)
		authenticateBytes, _ := b64.StdEncoding.DecodeString(ntlmChallengeString)

		auth, err := ntlm.ParseAuthenticateMessage(authenticateBytes, 2)
		if err == nil {
			err = session.ProcessAuthenticateMessage(auth)
			if err != nil {
				t.Errorf("Could not process authenticate message: %s\n", err)
				return
			} else {
				w.Write([]byte(secret + "itworksbrah"))
				//t.Log(receivedCredsString)
				return
			}
		} else {
			challenge, _ := session.GenerateChallengeMessage()
			w.Header().Add("WWW-Authenticate", `Basic realm="test"`)
			w.Header().Add("WWW-Authenticate", "NTLM "+b64.StdEncoding.EncodeToString(challenge.Bytes()))
			w.WriteHeader(401)
		}
	}
}

func basicAuthRequest(url string, testCase mockAuthTestCase, t *testing.T) string {
	creds := testCase.Creds
	credsEnc := b64.StdEncoding.EncodeToString([]byte(creds.UserName + ":" + creds.Password))

	// create ClusterSecretStore
	testStore := &esv1beta1.ClusterSecretStore{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterSecretStore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-store",
			Namespace: "default",
		},
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Webhook: &esv1beta1.WebhookProvider{
					URL: url,
					Headers: map[string]string{
						"Authorization": credsEnc,
					},
				},
			},
		},
	}

	// create HTTP client from ClusterSecretStore
	testProv := &Provider{}
	client, err := testProv.NewClient(context.Background(), testStore, nil, "testnamespace")
	if err != nil {
		t.Errorf("Error creating client: \n%q\n%q", testCase, err.Error())
		return "error"
	}

	// dummy testRef (unused in this test, but required)
	testRef := esv1beta1.ExternalSecretDataRemoteRef{
		Key: "dummy",
	}

	// perform request, exercising GetSecret
	resp, err := client.GetSecret(context.Background(), testRef)
	if err != nil {
		t.Errorf("Error retrieving secret:\n%s\n%s", testCase, err.Error())
	}

	return string(resp)

}

func ntlmAuthRequest(url string, testCase mockAuthTestCase, t *testing.T) string {
	//	creds := testCase.Creds
	//	credsEnc := b64.StdEncoding.EncodeToString([]byte(creds.UserName + ":" + creds.Password))

	// create ClusterSecretStore
	/*
		testStore := &esv1beta1.ClusterSecretStore{
			TypeMeta: metav1.TypeMeta{
				Kind: "ClusterSecretStore",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "webhook-store",
				Namespace: "default",
			},
			Spec: esv1beta1.SecretStoreSpec{
				Provider: &esv1beta1.SecretStoreProvider{
					Webhook: &esv1beta1.WebhookProvider{
						URL: url,
						Auth: &esv1beta1.AuthorizationProtocol{
							NTLM: &esv1beta1.NTLMProtocol{
								UserName: esmeta.SecretKeySelector{},
								Password: esmeta.SecretKeySelector{},
							},
						},
					},
				},
			},
		}

		// create HTTP client from ClusterSecretStore
		testProv := &Provider{}
		client, err := testProv.NewClient(context.Background(), testStore, nil, "testnamespace")
		if err != nil {
			t.Errorf("Error creating client: \n%q\n%q", testCase, err.Error())
			return "error"
		}

		// dummy testRef (unused in this test, but required)
		testRef := esv1beta1.ExternalSecretDataRemoteRef{
			Key: "dummy",
		}

		// perform request, exercising GetSecret
		resp, err := client.GetSecret(context.Background(), testRef)
		if err != nil {
			t.Errorf("Error retrieving secret:\n%s\n%s", testCase, err.Error())
		}

		return string(resp)
	*/
	client := http.Client{
		Transport: &httpntlm.NtlmTransport{
			Domain:   "",
			User:     testCase.Creds.UserName,
			Password: testCase.Creds.Password,
			// Configure RoundTripper if necessary, otherwise DefaultTransport is used
			RoundTripper: &http.Transport{
				// provide tls config
				//		TLSClientConfig: &tls.Config{},
				// other properties RoundTripper, see http.DefaultTransport
			},
		},
	}

	req, _ := http.NewRequest("Get", url, nil)
	req.SetBasicAuth(testCase.Creds.UserName, testCase.Creds.Password)
	//t.Log(req.Header.Get("Authorization"))

	res, _ := client.Do(req)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("Error")
	}
	return string(body)

}
