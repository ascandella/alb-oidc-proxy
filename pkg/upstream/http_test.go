package upstream

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("HTTP Upstream Suite", func() {

	const flushInterval5s = 5 * time.Second
	const flushInterval1s = 1 * time.Second

	const (
		contentType     = "Content-Type"
		contentLength   = "Content-Length"
		date            = "Date"
		acceptEncoding  = "Accept-Encoding"
		applicationJSON = "application/json"
		gapUpstream     = "Gap-Upstream-Address"
		gapAuth         = "Gap-Auth"
		gapSignature    = "Gap-Signature"
	)

	type httpUpstreamTableInput struct {
		id               string
		serverAddr       *string
		target           string
		method           string
		body             []byte
		signatureData    *options.SignatureData
		existingHeaders  map[string]string
		expectedResponse testHTTPResponse
		errorHandler     ProxyErrorHandler
	}

	DescribeTable("HTTP Upstream ServeHTTP",
		func(in *httpUpstreamTableInput) {
			buf := bytes.NewBuffer(in.body)
			req := httptest.NewRequest(in.method, in.target, buf)
			// Don't mock the remote Address
			req.RemoteAddr = ""

			for key, value := range in.existingHeaders {
				req.Header.Add(key, value)
			}

			rw := httptest.NewRecorder()

			flush := 1 * time.Second
			upstream := options.Upstream{
				ID:                    in.id,
				PassHostHeader:        true,
				ProxyWebSockets:       false,
				InsecureSkipTLSVerify: false,
				FlushInterval:         &flush,
			}

			Expect(in.serverAddr).ToNot(BeNil())
			u, err := url.Parse(*in.serverAddr)
			Expect(err).ToNot(HaveOccurred())

			handler := newHTTPUpstreamProxy(upstream, u, in.signatureData, in.errorHandler)
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedResponse.code))

			// Delete extra headers that aren't relevent to tests
			rw.Header().Del(date)
			rw.Header().Del(contentLength)
			Expect(rw.Header()).To(Equal(in.expectedResponse.header))

			body := rw.Body.Bytes()
			if rw.Code != http.StatusOK {
				Expect(string(body)).To(Equal(in.expectedResponse.raw))
				return
			}

			// Compare the reflected request to the upstream
			request := testHTTPRequest{}
			Expect(json.Unmarshal(body, &request)).To(Succeed())
			// Strip the accept header that is added by the HTTP Transport, for easier testing
			request.Header.Del(acceptEncoding)

			Expect(request).To(Equal(in.expectedResponse.request))
		},
		Entry("request a path on the server", &httpUpstreamTableInput{
			id:           "default",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/foo",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					gapUpstream: []string{"default"},
					contentType: []string{applicationJSON},
				},
				request: testHTTPRequest{
					Method:     "GET",
					URL:        "http://example.localhost/foo",
					Header:     map[string][]string{},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/foo",
				},
			},
		}),
		Entry("when the request has a body", &httpUpstreamTableInput{
			id:           "requestWithBody",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/withBody",
			method:       "POST",
			body:         []byte("body"),
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					gapUpstream: []string{"requestWithBody"},
					contentType: []string{applicationJSON},
				},
				request: testHTTPRequest{
					Method: "POST",
					URL:    "http://example.localhost/withBody",
					Header: map[string][]string{
						contentLength: []string{"4"},
					},
					Body:       []byte("body"),
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/withBody",
				},
			},
		}),
		Entry("when the upstream is unavailable", &httpUpstreamTableInput{
			id:           "unavailableUpstream",
			serverAddr:   &invalidServer,
			target:       "http://example.localhost/unavailableUpstream",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 502,
				header: map[string][]string{
					gapUpstream: []string{"unavailableUpstream"},
				},
				request: testHTTPRequest{},
			},
		}),
		Entry("when the upstream is unavailable and an error handler is set", &httpUpstreamTableInput{
			id:         "withErrorHandler",
			serverAddr: &invalidServer,
			target:     "http://example.localhost/withErrorHandler",
			method:     "GET",
			body:       []byte{},
			errorHandler: func(rw http.ResponseWriter, _ *http.Request, _ error) {
				rw.WriteHeader(502)
				rw.Write([]byte("error"))
			},
			expectedResponse: testHTTPResponse{
				code: 502,
				header: map[string][]string{
					gapUpstream: []string{"withErrorHandler"},
				},
				raw:     "error",
				request: testHTTPRequest{},
			},
		}),
		Entry("with a signature", &httpUpstreamTableInput{
			id:         "withSignature",
			serverAddr: &serverAddr,
			target:     "http://example.localhost/withSignature",
			method:     "GET",
			body:       []byte{},
			signatureData: &options.SignatureData{
				Hash: crypto.SHA256,
				Key:  "key",
			},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: []string{applicationJSON},
					gapUpstream: []string{"withSignature"},
				},
				request: testHTTPRequest{
					Method: "GET",
					URL:    "http://example.localhost/withSignature",
					Header: map[string][]string{
						gapAuth:      []string{""},
						gapSignature: []string{"sha256 osMWI8Rr0Zr5HgNq6wakrgJITVJQMmFN1fXCesrqrmM="},
					},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/withSignature",
				},
			},
		}),
		Entry("with existing headers", &httpUpstreamTableInput{
			id:           "existingHeaders",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/existingHeaders",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			existingHeaders: map[string]string{
				"Header1": "value1",
				"Header2": "value2",
			},
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					gapUpstream: []string{"existingHeaders"},
					contentType: []string{applicationJSON},
				},
				request: testHTTPRequest{
					Method: "GET",
					URL:    "http://example.localhost/existingHeaders",
					Header: map[string][]string{
						"Header1": []string{"value1"},
						"Header2": []string{"value2"},
					},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/existingHeaders",
				},
			},
		}),
	)

	It("ServeHTTP, when not passing a host header", func() {
		req := httptest.NewRequest("", "http://example.localhost/foo", nil)
		rw := httptest.NewRecorder()

		flush := 1 * time.Second
		upstream := options.Upstream{
			ID:                    "noPassHost",
			PassHostHeader:        false,
			ProxyWebSockets:       false,
			InsecureSkipTLSVerify: false,
			FlushInterval:         &flush,
		}

		u, err := url.Parse(serverAddr)
		Expect(err).ToNot(HaveOccurred())

		handler := newHTTPUpstreamProxy(upstream, u, nil, nil)
		httpUpstream, ok := handler.(*httpUpstreamProxy)
		Expect(ok).To(BeTrue())

		// Override the handler to just run the director and not actually send the request
		requestInterceptor := func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				proxy, ok := h.(*httputil.ReverseProxy)
				Expect(ok).To(BeTrue())
				proxy.Director(req)
			})
		}
		httpUpstream.handler = requestInterceptor(httpUpstream.handler)

		httpUpstream.ServeHTTP(rw, req)
		Expect(req.Host).To(Equal(strings.TrimPrefix(serverAddr, "http://")))
	})

	type newUpstreamTableInput struct {
		proxyWebSockets bool
		flushInterval   time.Duration
		skipVerify      bool
		sigData         *options.SignatureData
		errorHandler    func(http.ResponseWriter, *http.Request, error)
	}

	DescribeTable("newHTTPUpstreamProxy",
		func(in *newUpstreamTableInput) {
			u, err := url.Parse("http://upstream:1234")
			Expect(err).ToNot(HaveOccurred())

			upstream := options.Upstream{
				ID:                    "foo123",
				FlushInterval:         &in.flushInterval,
				InsecureSkipTLSVerify: in.skipVerify,
				ProxyWebSockets:       in.proxyWebSockets,
			}

			handler := newHTTPUpstreamProxy(upstream, u, in.sigData, in.errorHandler)
			upstreamProxy, ok := handler.(*httpUpstreamProxy)
			Expect(ok).To(BeTrue())

			Expect(upstreamProxy.auth != nil).To(Equal(in.sigData != nil))
			Expect(upstreamProxy.wsHandler != nil).To(Equal(in.proxyWebSockets))
			Expect(upstreamProxy.upstream).To(Equal(upstream.ID))
			Expect(upstreamProxy.handler).ToNot(BeNil())

			proxy, ok := upstreamProxy.handler.(*httputil.ReverseProxy)
			Expect(ok).To(BeTrue())
			Expect(proxy.FlushInterval).To(Equal(in.flushInterval))
			Expect(proxy.ErrorHandler != nil).To(Equal(in.errorHandler != nil))
			if in.skipVerify {
				Expect(proxy.Transport).To(Equal(&http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}))
			}
		},
		Entry("with proxy websockets", &newUpstreamTableInput{
			proxyWebSockets: true,
			flushInterval:   flushInterval1s,
			skipVerify:      false,
			sigData:         nil,
			errorHandler:    nil,
		}),
		Entry("with a non standard flush interval", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   flushInterval5s,
			skipVerify:      false,
			sigData:         nil,
			errorHandler:    nil,
		}),
		Entry("with a InsecureSkipTLSVerify", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   flushInterval1s,
			skipVerify:      true,
			sigData:         nil,
			errorHandler:    nil,
		}),
		Entry("with a SignatureData", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   flushInterval1s,
			skipVerify:      false,
			sigData:         &options.SignatureData{Hash: crypto.SHA256, Key: "secret"},
			errorHandler:    nil,
		}),
		Entry("with an error handler", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   flushInterval1s,
			skipVerify:      false,
			sigData:         nil,
			errorHandler: func(rw http.ResponseWriter, req *http.Request, arg3 error) {
				rw.WriteHeader(502)
			},
		}),
	)
})

type testHTTPResponse struct {
	code    int
	header  http.Header
	raw     string
	request testHTTPRequest
}

type testHTTPRequest struct {
	Method     string
	URL        string
	Header     http.Header
	Body       []byte
	Host       string
	RequestURI string
}

type testHTTPUpstream struct{}

func (t *testHTTPUpstream) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	requestBody := []byte{}
	if req.Body != http.NoBody {
		var err error
		requestBody, err = ioutil.ReadAll(req.Body)
		if err != nil {
			t.writeError(rw, err)
			return
		}
	}

	request := testHTTPRequest{
		Method:     req.Method,
		URL:        req.URL.String(),
		Header:     req.Header,
		Body:       requestBody,
		Host:       req.Host,
		RequestURI: req.RequestURI,
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.writeError(rw, err)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(data)
}

func (t *testHTTPUpstream) writeError(rw http.ResponseWriter, err error) {
	rw.WriteHeader(500)
	if err != nil {
		rw.Write([]byte(err.Error()))
	}
}
