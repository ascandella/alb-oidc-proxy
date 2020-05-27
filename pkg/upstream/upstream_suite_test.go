package upstream

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	filesDir      string
	server        *httptest.Server
	serverAddr    string
	invalidServer = "http://::1"
)

func TestUpstreamSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	log.SetOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Upstream Suite")
}

var _ = BeforeSuite(func() {
	// Set up files for serving via file servers
	dir, err := ioutil.TempDir("", "oauth2-proxy-upstream-suite")
	Expect(err).ToNot(HaveOccurred())
	Expect(ioutil.WriteFile(path.Join(dir, "foo"), []byte("foo"), 0644)).To(Succeed())
	Expect(ioutil.WriteFile(path.Join(dir, "bar"), []byte("bar"), 0644)).To(Succeed())
	Expect(os.Mkdir(path.Join(dir, "subdir"), 0644)).To(Succeed())
	Expect(ioutil.WriteFile(path.Join(dir, "subdir", "baz"), []byte("baz"), 0644)).To(Succeed())
	filesDir = dir

	// Set up a webserver that reflects requests
	server = httptest.NewServer(&testHTTPUpstream{})
	serverAddr = fmt.Sprintf("http://%s", server.Listener.Addr().String())
})

var _ = AfterSuite(func() {
	server.Close()
	os.RemoveAll(filesDir)
})
