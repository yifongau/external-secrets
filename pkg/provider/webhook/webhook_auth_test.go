package webhook

import (
	b64 "encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	//"github.com/Azure/go-ntlmssp"

	"github.com/vadimi/go-http-ntlm/v2"
	"github.com/vadimi/go-ntlm/ntlm"
)

// type mockAuthHandler func(secret string, validCreds creds, session ntlm.ServerSession, t *testing.T) http.HandlerFunc
type mockAuthTestPackage struct {
	ServerCreds   mockCreds
	ServerSecret  string
	TestContext   mockAuthTestContext
	TestRequest   mockAuthTestRequest
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

type mockAuthTestContext func(
	serverCreds mockCreds,
	serverSecret string,
	testRequest mockAuthTestRequest,
	loginAttempts []mockLoginAttempt,
	t *testing.T)

type mockAuthTestRequest func(
	url string,
	creds mockCreds,
	t *testing.T) string

func TestWebhookAuth(t *testing.T) {

	// define testing packages
	validCreds := mockCreds{"correctuser123", "correctpassword123"}
	invalidCreds := mockCreds{"incorrectuser123", "incorrectpassword123"}
	secret := "secret123"

	loginAttempts := []mockLoginAttempt{
		{validCreds, secret},
		{invalidCreds, "401"},
	}

	mockAuthTestPackages := map[string]mockAuthTestPackage{
		//	"BasicAuth": {basicAuthRequest, basicAuthHandler, authTestCases},
		"NTLM": {validCreds, secret, ntlmContext, ntlmRequest, loginAttempts},
	}

	for _, p := range mockAuthTestPackages {
		p.TestContext(p.ServerCreds, p.ServerSecret, p.TestRequest, p.LoginAttempts, t)
	}
}

func ntlmContext(creds mockCreds, secret string, testRequest mockAuthTestRequest, loginAttempts []mockLoginAttempt, t *testing.T) {

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
			if err == nil {
				err = session.ProcessAuthenticateMessage(auth)
				if err == nil {
					w.Write([]byte(secret))
				} else {
					w.Write([]byte("401"))
				}
			} else { // NEGOTIATE_MESSAGE, generate CHALLENGE_MESSESAGE
				challenge, _ := session.GenerateChallengeMessage()
				w.Header().Add("WWW-Authenticate", `Basic realm="test"`)
				w.Header().Add("WWW-Authenticate", "NTLM "+b64.StdEncoding.EncodeToString(challenge.Bytes()))
				w.WriteHeader(401)
			}
		}
	}))
	defer server.Close()

	for _, loginAttempt := range loginAttempts {
		result := testRequest(server.URL, loginAttempt.Creds, t)
		expect := loginAttempt.Expect
		if result != expect {
			t.Errorf("Test failed. Result: '%s' / Expected:  '%s'", result, expect)
		}
	}

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

/*
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
