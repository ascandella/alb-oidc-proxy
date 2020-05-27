package upstream

import (
	"crypto"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proxy Suite", func() {
	var upstreamServer http.Handler

	BeforeEach(func() {
		sigData := &options.SignatureData{Hash: crypto.SHA256, Key: "secret"}

		tmpl, err := template.New("").Parse("{{ .Title }}\n{{ .Message }}\n{{ .ProxyPrefix }}")
		Expect(err).ToNot(HaveOccurred())
		errorHandler := NewProxyErrorHandler(tmpl, "prefix")

		ok := http.StatusOK

		upstreams := options.Upstreams{
			{
				ID:   "http-backend",
				Path: "/http",
				URI:  serverAddr,
			},
			{
				ID:   "file-backend",
				Path: "/files",
				URI:  fmt.Sprintf("file:///%s", filesDir),
			},
			{
				ID:         "static-backend",
				Path:       "/static",
				Static:     true,
				StaticCode: &ok,
			},
			{
				ID:   "bad-http-backend",
				Path: "/bad-http",
				URI:  "http://::1",
			},
		}

		upstreamServer, err = NewProxy(upstreams, sigData, errorHandler)
		Expect(err).ToNot(HaveOccurred())
	})

	type proxyTableInput struct {
		target           string
		responseCode     int
		expectedUpstream string
	}

	DescribeTable("Proxy ServerHTTP",
		func(in *proxyTableInput) {
			req := httptest.NewRequest("", in.target, nil)
			rw := httptest.NewRecorder()
			upstreamServer.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.responseCode))
			Expect(rw.Header().Get("Gap-UpstreamAddress")).To(Equal([]string{in.expectedUpstream}))
		},
		Entry("with a request to the HTTP service", &proxyTableInput{
			target:           "http://example.localhost/http/1234",
			responseCode:     200,
			expectedUpstream: "http-backend",
		}),
	)
})
