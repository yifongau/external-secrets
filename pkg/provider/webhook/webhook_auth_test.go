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

type authTestCase struct {
	AuthMethod string
	Creds      creds
	Expected   string
}

type creds struct {
	userName string
	password string
}

func TestWebhookAuth(t *testing.T) {

	// declare dummy data
	validCreds := creds{"correctuser", "correctpassword"}
	invalidCreds := creds{"incorrectuser", "incorrectpassword"}
	secret := "thisIsTheSecret"

	// declare test cases
	authTestCases := map[string]authTestCase{
		"BasicAuth with correct creds": {
			AuthMethod: "BasicAuth",
			Creds:      validCreds,
			Expected:   secret,
		},
		"BasicAuth with incorrect creds": {
			AuthMethod: "BasicAuth",
			Creds:      invalidCreds,
			Expected:   "401",
		},
	}

	// create test server with mux
	mux := http.NewServeMux()
	basicAuthEndpoint := "/BasicAuth"
	mux.HandleFunc(basicAuthEndpoint, basicAuthHandler(secret, validCreds))
	authTestServer := httptest.NewServer(mux)
	defer authTestServer.Close()

	// parse test cases and execute tests
	for _, testCase := range authTestCases {
		if testCase.AuthMethod == "BasicAuth" {
			url := authTestServer.URL + basicAuthEndpoint
			runAuthTestCase(url, testCase, t)
		}
	}
}

func runAuthTestCase(url string, testCase authTestCase, t *testing.T) {
	result := basicAuthRequest(url, testCase, t)
	expected := testCase.Expected

	if result != expected {
		t.Errorf("got %q, expected %q", result, expected)
	}
}

func basicAuthHandler(secret string, validCreds creds) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validCredsString := validCreds.userName + ":" + validCreds.password
		receivedCreds, _ := b64.StdEncoding.DecodeString(r.Header.Get("Authorization"))
		if string(receivedCreds) != validCredsString {
			w.Write([]byte("401"))
		} else if string(receivedCreds) == validCredsString {
			w.Write([]byte(secret))
		}
	}
}

func basicAuthRequest(url string, testCase authTestCase, t *testing.T) string {
	creds := testCase.Creds
	credsEnc := b64.StdEncoding.EncodeToString([]byte(creds.userName + ":" + creds.password))

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
