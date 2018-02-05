package netrc

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type NetrcSuite struct{}

var _ = Suite(&NetrcSuite{})

func (s *NetrcSuite) TestLogin(c *C) {
	f, err := Parse("./examples/login.netrc")
	c.Assert(err, IsNil)
	heroku := f.Machine("api.heroku.com")
	c.Check(heroku.Get("login"), Equals, "jeff@heroku.com")
	c.Check(heroku.Get("password"), Equals, "foo")

	heroku2 := f.MachineAndLogin("api.heroku.com", "jeff2@heroku.com")
	c.Check(heroku2.Get("login"), Equals, "jeff2@heroku.com")
	c.Check(heroku2.Get("password"), Equals, "bar")
}

func (s *NetrcSuite) TestSampleMulti(c *C) {
	f, err := Parse("./examples/sample_multi.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("m").Get("login"), Equals, "lm")
	c.Check(f.Machine("m").Get("password"), Equals, "pm")
	c.Check(f.Machine("n").Get("login"), Equals, "ln")
	c.Check(f.Machine("n").Get("password"), Equals, "pn")
}

func (s *NetrcSuite) TestSampleMultiWithDefault(c *C) {
	f, err := Parse("./examples/sample_multi_with_default.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("m").Get("login"), Equals, "lm")
	c.Check(f.Machine("m").Get("password"), Equals, "pm")
	c.Check(f.Machine("n").Get("login"), Equals, "ln")
	c.Check(f.Machine("n").Get("password"), Equals, "pn")
}

func (s *NetrcSuite) TestNewlineless(c *C) {
	f, err := Parse("./examples/newlineless.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("m").Get("login"), Equals, "l")
	c.Check(f.Machine("m").Get("password"), Equals, "p")
}

func (s *NetrcSuite) TestBadDefaultOrder(c *C) {
	f, err := Parse("./examples/bad_default_order.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("mail.google.com").Get("login"), Equals, "joe@gmail.com")
	c.Check(f.Machine("mail.google.com").Get("password"), Equals, "somethingSecret")
	c.Check(f.Machine("ray").Get("login"), Equals, "demo")
	c.Check(f.Machine("ray").Get("password"), Equals, "mypassword")
}

func (s *NetrcSuite) TestDefaultOnly(c *C) {
	f, err := Parse("./examples/default_only.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("default").Get("login"), Equals, "ld")
	c.Check(f.Machine("default").Get("password"), Equals, "pd")
}

func (s *NetrcSuite) TestGood(c *C) {
	f, err := Parse("./examples/good.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("mail.google.com").Get("login"), Equals, "joe@gmail.com")
	c.Check(f.Machine("mail.google.com").Get("account"), Equals, "justagmail")
	c.Check(f.Machine("mail.google.com").Get("password"), Equals, "somethingSecret")
}

func (s *NetrcSuite) TestPassword(c *C) {
	f, err := Parse("./examples/password.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("m").Get("password"), Equals, "p")
}

func (s *NetrcSuite) TestPermissive(c *C) {
	f, err := Parse("./examples/permissive.netrc")
	c.Assert(err, IsNil)
	c.Check(f.Machine("m").Get("login"), Equals, "l")
	c.Check(f.Machine("m").Get("password"), Equals, "p")
}
