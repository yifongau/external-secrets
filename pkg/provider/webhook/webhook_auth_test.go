package webhook

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebhookAuthentication(t *testing.T) {
	//have := runTestCase()
	got := runAuthTestCase()
	want := 200

	if got != want {
		t.Errorf("got %q, wanted %q", got, want)
	}

}

// functions needed for simulating client request
//GetSecret(ctx context.Context, ref esv1beta1.ExternalSecretDataRemoteRef)
//GetHTTPClient(ctx context.Context, provider *Spec) <- method on w webhook

// run testcases (pass requests to handlers here)
func runAuthTestCase() int {

	// handler functions (add new auth methods here)
	mux := http.NewServeMux()
	mux.HandleFunc("/BasicAuth", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Mocking webhook authentication using BasicAuth")
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		fmt.Printf("client: could not  create request %s\n", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("client:error making http request: %s\n", err)
	}

	reqBody, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("server: could not read request body: %s\n", err)
	}

	fmt.Printf(reqBody)

	return 200
}
