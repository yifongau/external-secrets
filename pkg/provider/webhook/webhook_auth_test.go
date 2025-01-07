package webhook

import (
	"context"
	b64 "encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type mockAuthPackage struct {
	Request   mockAuthRequest
	Handler   mockAuthHandler
	TestCases []mockAuthTestCase
}

type mockAuthRequest func(url string, testCase mockAuthTestCase, t *testing.T) string
type mockAuthHandler func(secret string, validCreds creds) http.HandlerFunc
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
	validCreds := creds{"correctuser", "correctpassword"}
	invalidCreds := creds{"incorrectuser", "incorrectpassword"}
	secret := "thisIsTheSecret"

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

	// start test server with mux
	mux := http.NewServeMux()
	for name, mockAuthPackage := range mockAuthPackages {
		endpoint := "/" + name
		mux.HandleFunc(endpoint, mockAuthPackage.Handler(secret, validCreds))
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

func basicAuthHandler(secret string, validCreds creds) http.HandlerFunc {
	// use closure so we can pass the handler the testdata at runtime
	return func(w http.ResponseWriter, r *http.Request) {
		validCredsString := b64.StdEncoding.EncodeToString([]byte(validCreds.UserName + ":" + validCreds.Password))
		receivedCredsString := r.Header.Get("Authorization")

		if receivedCredsString != validCredsString {
			w.Write([]byte("401"))
		} else if receivedCredsString == validCredsString {
			w.Write([]byte(secret))
		}
	}
}

func ntlmAuthHandler(secret string, validCreds creds) http.HandlerFunc {
	// use closure so we can pass the handler the testdata at runtime
	return func(w http.ResponseWriter, r *http.Request) {
		validCredsString := b64.StdEncoding.EncodeToString([]byte(validCreds.UserName + ":" + validCreds.Password))
		receivedCredsString := r.Header.Get("Authorization")

		if receivedCredsString != validCredsString {
			w.Write([]byte("401"))
		} else if receivedCredsString == validCredsString {
			w.Write([]byte(secret))
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
