package bgptest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func checkAdjout(t *testing.T, c *bgpTest) {
	// should not send routes from ibgp to ibgp peers
	r, err := c.getCounter("ibgp-g1", "ibgp-r1")
	assert.Nil(t, err)
	assert.Equal(t, r.received, uint64(0))
	r, err = c.getCounter("ibgp-g2", "ibgp-r1")
	assert.Nil(t, err)
	assert.Equal(t, r.received, uint64(0))

	has, _ := c.waitForPath("ibgp-r1", adjout, "ibgp-g2", "10.0.0.0/24", 50)
	assert.False(t, has)
	has, _ = c.waitForPath("ibgp-r1", adjout, "ibgp-g1", "10.0.1.0/24", 50)
	assert.False(t, has)
}

func checkGlobalrib(t *testing.T, c *bgpTest) {
	err := c.addPath("ibgp-g1", "10.0.0.0/24")
	assert.Nil(t, err)
	err = c.addPath("ibgp-g2", "10.0.1.0/24")
	assert.Nil(t, err)
	has, _ := c.waitForPath("ibgp-r1", global, "", "10.0.0.0/24", 50)
	assert.True(t, has)
	has, _ = c.waitForPath("ibgp-r1", global, "", "10.0.1.0/24", 50)
	assert.True(t, has)
}

func waitForEstablish(t *testing.T, c *bgpTest) {
	c.waitForEstablish("ibgp-g1")
	c.waitForEstablish("ibgp-g2")
}

func TestIbgp(t *testing.T) {
	rustyimage := rustybgpImage
	if n := os.Getenv(rustbgyImageEnv); n != "" {
		rustyimage = n
	}
	c, err := newBgpTest()
	assert.Nil(t, err)
	err = c.createPeer("ibgp-r1", rustyimage, 1)
	assert.Nil(t, err)
	err = c.createPeer("ibgp-g1", "tomo/gobgp", 1)
	assert.Nil(t, err)
	err = c.createPeer("ibgp-g2", "tomo/gobgp", 1)
	assert.Nil(t, err)

	// test rustybgp active connect
	err = c.connectPeers("ibgp-g1", "ibgp-r1", true)
	assert.Nil(t, err)
	err = c.connectPeers("ibgp-g2", "ibgp-r1", false)
	assert.Nil(t, err)
	err = c.connectPeers("ibgp-g1", "ibgp-g2", false)
	assert.Nil(t, err)

	waitForEstablish(t, c)
	checkGlobalrib(t, c)
	checkAdjout(t, c)
	//	c.Stop()
}
