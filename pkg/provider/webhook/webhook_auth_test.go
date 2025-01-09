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

// type mockAuthHandler func(secret string, validCreds creds, session ntlm.ServerSession, t *testing.T) http.HandlerFunc
type mockAuthTestPackage struct {
	ServerCreds   mockCreds
	ServerSecret  string
	TestServer    mockAuthTestServer
	Request       mockAuthRequest
	LoginAttempts []mockLoginAttempt
}

type mockLoginAttempt struct {
	Creds  mockCreds
	Expect string
}

type mockCreds struct {
	UserName string
	Password string
}

type mockAuthTestServer func(
	serverCreds mockCreds,
	serverSecret string,
	t *testing.T) *httptest.Server

type mockAuthRequest func(
	url string,
	creds mockCreds,
	t *testing.T) string

func TestWebhookAuth(t *testing.T) {

	// define test cases
	validCreds := mockCreds{"correctuser123", "correctpassword123"}
	invalidCreds := mockCreds{"incorrectuser123", "incorrectpassword123"}
	secret := "secret123"

	loginAttempts := []mockLoginAttempt{
		{validCreds, secret},
		{invalidCreds, "401"},
	}

	testPackages := map[string]mockAuthTestPackage{
		"BasicAuth": {validCreds, secret, basicAuthServer, basicAuthRequest, loginAttempts},
		"NTLM":      {validCreds, secret, ntlmServer, ntlmRequest, loginAttempts},
	}

	// execute test cases
	for _, p := range testPackages {
		server := p.TestServer(p.ServerCreds, p.ServerSecret, t)
		defer server.Close()

		for _, loginAttempt := range loginAttempts {
			result := p.Request(server.URL, loginAttempt.Creds, t)
			expect := loginAttempt.Expect
			if result != expect {
				t.Errorf("Test failed. Result: '%s' / Expected:  '%s'", result, expect)
			}
		}

	}
}

func ntlmServer(creds mockCreds, secret string, t *testing.T) *httptest.Server {

	session, _ := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
	session.SetUserInfo(creds.UserName, creds.Password, "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		reqAuthString := r.Header.Get("Authorization")
		if reqAuthString == "" {
			w.Write([]byte("Empty Authorization header"))

		} else {
			ntlmChallengeString := strings.Replace(reqAuthString, "NTLM ", "", -1)
			authenticateBytes, _ := b64.StdEncoding.DecodeString(ntlmChallengeString)

			auth, err := ntlm.ParseAuthenticateMessage(authenticateBytes, 2)
			if err != nil { //  IS NEGOTIATE_MESSAGE, reply with CHALLENGE_MESSAGE
				challenge, _ := session.GenerateChallengeMessage()
				w.Header().Add("WWW-Authenticate", `Basic realm="test"`)
				w.Header().Add("WWW-Authenticate", "NTLM "+b64.StdEncoding.EncodeToString(challenge.Bytes()))
				w.WriteHeader(401)

			} else { // IS AUTHENTICATE_MESSAGE, authenticate
				err = session.ProcessAuthenticateMessage(auth)
				if err == nil {
					w.Write([]byte(secret + "hello"))
				} else {
					w.Write([]byte("401" + "hello"))
				}

			}
		}
	}))
	return server

}

func ntlmRequest(url string, creds mockCreds, t *testing.T) string {

	client := http.Client{
		Transport: &httpntlm.NtlmTransport{
			Domain:   "",
			User:     creds.UserName,
			Password: creds.Password,
			// Configure RoundTripper if necessary, otherwise DefaultTransport is used
			RoundTripper: &http.Transport{
				// provide tls config
				//		TLSClientConfig: &tls.Config{},
				// other properties RoundTripper, see http.DefaultTransport
			},
		},
	}

	req, _ := http.NewRequest("Get", url, nil)
	req.SetBasicAuth(creds.UserName, creds.Password)
	//t.Log(req.Header.Get("Authorization"))

	res, _ := client.Do(req)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("Error")
	}
	return string(body)
}

func basicAuthServer(creds mockCreds, secret string, t *testing.T) *httptest.Server {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validAuthString := b64.StdEncoding.EncodeToString([]byte(creds.UserName + ":" + creds.Password))
		reqAuthString := r.Header.Get("Authorization")

		if reqAuthString == "" {
			w.Write([]byte("Empty Authorization header"))

		} else {
			if reqAuthString == validAuthString {
				w.Write([]byte(secret))
			} else {
				w.Write([]byte("401"))
			}
		}
	}))

	return server

}

func basicAuthRequest(url string, creds mockCreds, t *testing.T) string {
	reqAuthString := b64.StdEncoding.EncodeToString([]byte(creds.UserName + ":" + creds.Password))

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
						"Authorization": reqAuthString,
					},
				},
			},
		},
	}

	// create HTTP client from ClusterSecretStore
	testProv := &Provider{}
	client, err := testProv.NewClient(context.Background(), testStore, nil, "testnamespace")
	if err != nil {
		t.Errorf("Error creating client: %q", err)
		return "error"
	}

	// dummy testRef (unused in this test, but required)
	testRef := esv1beta1.ExternalSecretDataRemoteRef{Key: "dummy"}

	// perform request, exercising GetSecret
	resp, err := client.GetSecret(context.Background(), testRef)
	if err != nil {
		t.Errorf("Error retrieving secret:%s", err)
	}
	return string(resp)

}

/*




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
*/
