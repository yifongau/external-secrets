/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package webhook

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	tpl "text/template"

	"github.com/PaesslerAG/jsonpath"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/pkg/constants"
	"github.com/external-secrets/external-secrets/pkg/metrics"
	"github.com/external-secrets/external-secrets/pkg/template/v2"
	"github.com/external-secrets/external-secrets/pkg/utils"
)

type Webhook struct {
	Kube          client.Client
	Namespace     string
	StoreKind     string
	HTTP          *http.Client
	EnforceLabels bool
	ClusterScoped bool
}

func (w *Webhook) getStoreSecret(ctx context.Context, ref SecretKeySelector) (*corev1.Secret, error) {
	ke := client.ObjectKey{
		Name:      ref.Name,
		Namespace: w.Namespace,
	}
	if w.ClusterScoped {
		if ref.Namespace == nil {
			return nil, fmt.Errorf("no namespace on ClusterScoped webhook secret %s", ref.Name)
		}
		ke.Namespace = *ref.Namespace
	}
	secret := &corev1.Secret{}
	if err := w.Kube.Get(ctx, ke, secret); err != nil {
		return nil, fmt.Errorf("failed to get clustersecretstore webhook secret %s: %w", ref.Name, err)
	}
	if w.EnforceLabels {
		expected, ok := secret.Labels["external-secrets.io/type"]
		if !ok {
			return nil, errors.New("secret does not contain needed label 'external-secrets.io/type: webhook'. Update secret label to use it with webhook")
		}
		if expected != "webhook" {
			return nil, errors.New("secret type is not 'webhook'")
		}
	}
	return secret, nil
}
func (w *Webhook) GetSecretMap(ctx context.Context, provider *Spec, ref *esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	result, err := w.GetWebhookData(ctx, provider, ref)
	if err != nil {
		return nil, err
	}
	// We always want json here, so just parse it out
	jsondata := any(nil)
	if err := json.Unmarshal(result, &jsondata); err != nil {
		return nil, fmt.Errorf("failed to parse response json: %w", err)
	}
	// Get subdata via jsonpath, if given
	if provider.Result.JSONPath != "" {
		jsondata, err = jsonpath.Get(provider.Result.JSONPath, jsondata)
		if err != nil {
			return nil, fmt.Errorf("failed to get response path %s: %w", provider.Result.JSONPath, err)
		}
	}
	// If the value is a string, try to parse it as json
	jsonstring, ok := jsondata.(string)
	if ok {
		// This could also happen if the response was a single json-encoded string
		// but that is an extremely unlikely scenario
		if err := json.Unmarshal([]byte(jsonstring), &jsondata); err != nil {
			return nil, fmt.Errorf("failed to parse response json from jsonpath: %w", err)
		}
	}
	// Use the data as a key-value map
	jsonvalue, ok := jsondata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("failed to get response (wrong type: %T)", jsondata)
	}
	// Change the map of generic objects to a map of byte arrays
	values := make(map[string][]byte)
	for rKey := range jsonvalue {
		values[rKey], err = utils.GetByteValueFromMap(jsonvalue, rKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get response for key '%s': %w", rKey, err)
		}
	}
	return values, nil
}

func (w *Webhook) GetTemplateData(ctx context.Context, ref *esv1.ExternalSecretDataRemoteRef, secrets []Secret, urlEncode bool) (map[string]map[string]string, error) {
	data := map[string]map[string]string{}
	if ref != nil {
		if urlEncode {
			data["remoteRef"] = map[string]string{
				"key":      url.QueryEscape(ref.Key),
				"version":  url.QueryEscape(ref.Version),
				"property": url.QueryEscape(ref.Property),
			}
		} else {
			data["remoteRef"] = map[string]string{
				"key":      ref.Key,
				"version":  ref.Version,
				"property": ref.Property,
			}
		}
	}

	if err := w.getTemplatedSecrets(ctx, secrets, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (w *Webhook) GetTemplatePushData(ctx context.Context, ref esv1.PushSecretData, secrets []Secret, urlEncode bool) (map[string]map[string]string, error) {
	data := map[string]map[string]string{}
	if ref != nil {
		if urlEncode {
			data["remoteRef"] = map[string]string{
				"remoteKey": url.QueryEscape(ref.GetRemoteKey()),
			}
			if v := ref.GetSecretKey(); v != "" {
				data["remoteRef"]["secretKey"] = url.QueryEscape(v)
			}
		} else {
			data["remoteRef"] = map[string]string{
				"remoteKey": ref.GetRemoteKey(),
			}
			if v := ref.GetSecretKey(); v != "" {
				data["remoteRef"]["secretKey"] = v
			}
		}
	}

	if err := w.getTemplatedSecrets(ctx, secrets, data); err != nil {
		return nil, err
	}

	return data, nil
}

func (w *Webhook) getTemplatedSecrets(ctx context.Context, secrets []Secret, data map[string]map[string]string) error {
	for _, secref := range secrets {
		if _, ok := data[secref.Name]; !ok {
			data[secref.Name] = make(map[string]string)
		}
		secret, err := w.getStoreSecret(ctx, secref.SecretRef)
		if err != nil {
			return err
		}
		for sKey, sVal := range secret.Data {
			data[secref.Name][sKey] = string(sVal)
		}
	}

	return nil
}

func (w *Webhook) GetWebhookData(ctx context.Context, provider *Spec, ref *esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if w.HTTP == nil {
		return nil, errors.New("http client not initialized")
	}

	escapedData, err := w.GetTemplateData(ctx, ref, provider.Secrets, true)
	if err != nil {
		return nil, err
	}
	rawData, err := w.GetTemplateData(ctx, ref, provider.Secrets, false)
	if err != nil {
		return nil, err
	}

	method := provider.Method
	if method == "" {
		method = http.MethodGet
	}
	url, err := ExecuteTemplateString(provider.URL, escapedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}
	body, err := ExecuteTemplate(provider.Body, rawData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse body: %w", err)
	}

	return w.executeRequest(ctx, provider, body.Bytes(), url, method, rawData)
}

func (w *Webhook) PushWebhookData(ctx context.Context, provider *Spec, data []byte, remoteKey esv1.PushSecretData) error {
	if w.HTTP == nil {
		return errors.New("http client not initialized")
	}

	method := provider.Method
	if method == "" {
		method = http.MethodPost
	}

	escapedData, err := w.GetTemplatePushData(ctx, remoteKey, provider.Secrets, true)
	if err != nil {
		return err
	}
	escapedData["remoteRef"][remoteKey.GetRemoteKey()] = url.QueryEscape(string(data))

	rawData, err := w.GetTemplatePushData(ctx, remoteKey, provider.Secrets, false)
	if err != nil {
		return err
	}
	rawData["remoteRef"][remoteKey.GetRemoteKey()] = string(data)

	url, err := ExecuteTemplateString(provider.URL, escapedData)
	if err != nil {
		return fmt.Errorf("failed to parse url: %w", err)
	}

	bodyt := provider.Body
	if bodyt == "" {
		bodyt = fmt.Sprintf("{{ .remoteRef.%s }}", remoteKey.GetRemoteKey())
	}
	body, err := ExecuteTemplate(bodyt, rawData)
	if err != nil {
		return fmt.Errorf("failed to parse body: %w", err)
	}

	if _, err := w.executeRequest(ctx, provider, body.Bytes(), url, method, rawData); err != nil {
		return fmt.Errorf("failed to push webhook data: %w", err)
	}

	return nil
}

func (w *Webhook) executeRequest(ctx context.Context, provider *Spec, data []byte, url, method string, rawData map[string]map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	for hKey, hValueTpl := range provider.Headers {
		hValue, err := ExecuteTemplateString(hValueTpl, rawData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse header %s: %w", hKey, err)
		}
		req.Header.Add(hKey, hValue)
	}

	resp, err := w.HTTP.Do(req)
	metrics.ObserveAPICall(constants.ProviderWebhook, constants.CallWebhookHTTPReq, err)
	if err != nil {
		return nil, fmt.Errorf("failed to call endpoint: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode == 404 {
		return nil, esv1.NoSecretError{}
	}

	if resp.StatusCode == http.StatusNotModified {
		return nil, esv1.NotModifiedError{}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("endpoint gave error %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (w *Webhook) GetHTTPClient(ctx context.Context, provider *Spec) (*http.Client, error) {
	client := &http.Client{}
	if provider.Timeout != nil {
		client.Timeout = provider.Timeout.Duration
	}
	if len(provider.CABundle) == 0 && provider.CAProvider == nil {
		// No need to process ca stuff if it is not there
		return client, nil
	}
	caCertPool, err := w.GetCACertPool(ctx, provider)
	if err != nil {
		return nil, err
	}

	tlsConf := &tls.Config{
		RootCAs:       caCertPool,
		MinVersion:    tls.VersionTLS12,
		Renegotiation: tls.RenegotiateOnceAsClient,
	}
	client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	return client, nil
}

func (w *Webhook) GetCACertPool(ctx context.Context, provider *Spec) (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	ca, err := utils.FetchCACertFromSource(ctx, utils.CreateCertOpts{
		CABundle:   provider.CABundle,
		CAProvider: provider.CAProvider,
		StoreKind:  w.StoreKind,
		Namespace:  w.Namespace,
		Client:     w.Kube,
	})
	if err != nil {
		return nil, err
	}
	ok := caCertPool.AppendCertsFromPEM(ca)
	if !ok {
		return nil, errors.New("failed to append cabundle")
	}

	return caCertPool, nil
}

func ExecuteTemplateString(tmpl string, data map[string]map[string]string) (string, error) {
	result, err := ExecuteTemplate(tmpl, data)
	if err != nil {
		return "", err
	}
	return result.String(), nil
}

func ExecuteTemplate(tmpl string, data map[string]map[string]string) (bytes.Buffer, error) {
	var result bytes.Buffer
	if tmpl == "" {
		return result, nil
	}
	urlt, err := tpl.New("webhooktemplate").Funcs(template.FuncMap()).Parse(tmpl)
	if err != nil {
		return result, err
	}
	if err := urlt.Execute(&result, data); err != nil {
		return result, err
	}
	return result, nil
}
