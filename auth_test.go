package dbpasswd

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type DBPasswdSuite struct {}
var _ = Suite(&DBPasswdSuite{})

func (a *DBPasswdSuite) TestX(c *C) {
	c.Check(true, Equals, true)
}
