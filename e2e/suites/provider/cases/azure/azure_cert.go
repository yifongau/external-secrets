/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
limitations under the License.
*/
package azure

import (
	"fmt"

	// nolint
	. "github.com/onsi/ginkgo/v2"
	v1 "k8s.io/api/core/v1"

	// nolint
	"github.com/external-secrets/external-secrets-e2e/framework"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// azure keyvault type=cert should get a certificate from the api.
var _ = Describe("[azure]", Label("azure", "keyvault", "cert"), func() {
	f := framework.New("eso-azure-certtype")
	prov := newFromEnv(f)
	var certBytes []byte
	var certName string

	BeforeEach(func() {
		certName = fmt.Sprintf("%s-%s", f.Namespace.Name, "certtest")
		prov.CreateCertificate(certName)
		certBytes = prov.GetCertificate(certName)
	})

	AfterEach(func() {
		prov.DeleteCertificate(certName)
	})

	ff := framework.TableFuncWithExternalSecret(f, prov)
	It("should sync keyvault objects with type=cert", func() {
		ff(func(tc *framework.TestCase) {
			secretKey := "azkv-cert"

			tc.ExpectedSecret = &v1.Secret{
				Type: v1.SecretTypeOpaque,
				Data: map[string][]byte{
					secretKey: certBytes,
				},
			}
			tc.ExternalSecret.Spec.Data = []esv1.ExternalSecretData{
				{
					SecretKey: secretKey,
					RemoteRef: esv1.ExternalSecretDataRemoteRef{
						Key: "cert/" + certName,
					},
				},
			}
		})
	})

})
