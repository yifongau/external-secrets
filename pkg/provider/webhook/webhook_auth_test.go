package webhook

import (
	"context"
	b64 "encoding/base64"
	"io"
	//"k8s.io/client-go/kubernetes/scheme"
	"net/http"
	"net/http/httptest"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"strings"
	"testing"

	"github.com/Azure/go-ntlmssp"
	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/vadimi/go-http-ntlm/v2"
	"github.com/vadimi/go-ntlm/ntlm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

		for _, loginAttempt := range p.LoginAttempts {
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
		/*
			for name, values := range r.Header {
				t.Log(name, values)

			}

			reqEncoding := r.Header.Get("Accept-Encoding")
			var reqAuthString string
			switch reqEncoding {
			case "gzip":
				t.Log(reqEncoding)
				reader, _ := io.ReadAll(r.Body.Header.Get())
				t.Log(string(reader))

			default:
				reqAuthString = r.Header.Get("Authorization")
			}*/

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

	testAuthSecretName := "ntlmTestAuthSecret"
	testNamespace := "default"

	// ntlm clustersecretstore takes credentials from a secret,
	// so we need to create a fake client that mocks retrieval of fake secret.
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testAuthSecretName,
			Labels: map[string]string{
				"external-secrets.io/type": "webhook",
			},
		},
		Data: map[string][]byte{
			"userName": []byte(creds.UserName),
			"password": []byte(creds.Password),
		},
	}

	fakeClient := fake.NewClientBuilder().WithObjects(secret).Build()

	//t.Log("y hello" + string(foundSecret.Data["userName"]))

	// create ClusterSecretStore
	testStore := &esv1beta1.ClusterSecretStore{
		TypeMeta: metav1.TypeMeta{
			Kind: "ClusterSecretStore",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "webhook-store",
			Namespace: testNamespace,
		},
		Spec: esv1beta1.SecretStoreSpec{
			Provider: &esv1beta1.SecretStoreProvider{
				Webhook: &esv1beta1.WebhookProvider{
					URL: url,
					Auth: &esv1beta1.AuthorizationProtocol{
						NTLM: &esv1beta1.NTLMProtocol{
							UserName: esmeta.SecretKeySelector{
								Name:      testAuthSecretName,
								Namespace: &testNamespace,
								Key:       "userName",
							},
							Password: esmeta.SecretKeySelector{
								Name:      testAuthSecretName,
								Namespace: &testNamespace,
								Key:       "password",
							},
						},
					},
				},
			},
		},
	}

	//t.Log(testStore)
	//	secretRef := testStore.Spec.Provider.Webhook.Auth.NTLM.UserName
	//	t.Log(secretRef)
	// create HTTP client from ClusterSecretStore
	testProv := &Provider{}
	client, err := testProv.NewClient(context.Background(), testStore, fakeClient, "testnamespace")
	if err != nil {
		t.Errorf("Error creating client: %q", err)
		return "error"
	}

	//dummy testRef (unused in this test, but required)
	testRef := esv1beta1.ExternalSecretDataRemoteRef{Key: "dummy"}

	//perform request, exercising GetSecret
	resp, err := client.GetSecret(context.Background(), testRef)
	if err != nil {
		t.Errorf("Error retrieving secret:%s", err)
	}

	return string(resp)

	//return "debug"
}

func ntlmSimpleRequestNew(url string, creds mockCreds, t *testing.T) string {

	client := http.Client{
		Transport: &httpntlm.NtlmTransport{
			Domain:       "",
			User:         creds.UserName,
			Password:     creds.Password,
			RoundTripper: &http.Transport{},
		},
	}

	req, _ := http.NewRequest("Get", url, nil)
	res, _ := client.Do(req)
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Errorf("Error")
	}
	return string(body)
}

func ntlmSimpleRequestOld(url string, creds mockCreds, t *testing.T) string {
	/*
		client := http.Client{
			Transport: &httpntlm.NtlmTransport{
				Domain:       "",
				User:         creds.UserName,
				Password:     creds.Password,
				RoundTripper: &http.Transport{},
			},
		}

		req, _ := http.NewRequest("Get", url, nil)
		res, _ := client.Do(req)
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Errorf("Error")
		}*/

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{},
		},
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(creds.UserName, creds.Password)
	res, _ := client.Do(req)

	bodyBytes, _ := io.ReadAll(res.Body)

	return string(bodyBytes)
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
