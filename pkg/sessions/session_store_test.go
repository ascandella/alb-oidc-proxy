package sessions_test

import (
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions"
	sessionscookie "github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/redis"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSessionStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SessionStore")
}

var _ = Describe("NewSessionStore", func() {
	var opts *options.SessionOptions
	var cookieOpts *options.CookieOptions

	BeforeEach(func() {
		opts = &options.SessionOptions{}

		// Set default options in CookieOptions
		cookieOpts = &options.CookieOptions{
			Name:     "_oauth2_proxy",
			Path:     "/",
			Expire:   time.Duration(168) * time.Hour,
			Refresh:  time.Duration(1) * time.Hour,
			Secure:   true,
			HTTPOnly: true,
			SameSite: "",
		}
	})

	Context("with type 'cookie'", func() {
		BeforeEach(func() {
			opts.Type = options.CookieSessionStoreType
		})

		It("creates a cookie.SessionStore", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(ss).To(BeAssignableToTypeOf(&sessionscookie.SessionStore{}))
		})
	})

	Context("with type 'redis'", func() {
		BeforeEach(func() {
			opts.Type = options.RedisSessionStoreType
			opts.Redis.ConnectionURL = "redis://"
		})

		It("creates a redis.SessionStore", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(ss).To(BeAssignableToTypeOf(&redis.SessionStore{}))
		})
	})

	Context("with an invalid type", func() {
		BeforeEach(func() {
			opts.Type = "invalid-type"
		})

		It("returns an error", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("unknown session store type 'invalid-type'"))
			Expect(ss).To(BeNil())
		})
	})
})
