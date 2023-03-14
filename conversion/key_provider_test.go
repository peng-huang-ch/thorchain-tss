package conversion

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	. "gopkg.in/check.v1"
)

const testPriKey = "OTI4OTdkYzFjMWFhMjU3MDNiMTE4MDM1OTQyY2Y3MDVkOWFhOGIzN2JlOGIwOWIwMTZjYTkxZjNjOTBhYjhlYQ=="

type KeyProviderTestSuite struct{}

var _ = Suite(&KeyProviderTestSuite{})

func TestGetPubKeysFromPeerIDs(t *testing.T) {
	input := []string{
		"16Uiu2HAmBdJRswX94UwYj6VLhh4GeUf9X3SjBRgTqFkeEMLmfk2M",
		"16Uiu2HAkyR9dsFqkj1BqKw8ZHAUU2yur6ZLRJxPTiiVYP5uBMeMG",
	}
	result, err := GetPubKeysFromPeerIDs(input)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	assert.Len(t, result, 2)
	assert.Equal(t, "02f0b597f54b5b9bbec363426d8206ed045343afee34918137d9520d635ca7f16a", result[0])
	assert.Equal(t, "023b4c7029cc9375ba8ff42f1d258eee6c492e96775cfc6d130db8fead5d3f800b", result[1])
	input1 := append(input, "whatever")
	result, err = GetPubKeysFromPeerIDs(input1)
	assert.NotNil(t, err)
	assert.Nil(t, result)
}

func (*KeyProviderTestSuite) TestGetPriKey(c *C) {
	pk, err := GetPriKey("whatever")
	c.Assert(err, NotNil)
	c.Assert(pk, IsNil)
	input := hex.EncodeToString([]byte("whatever"))
	pk, err = GetPriKey(input)
	c.Assert(err, NotNil)
	c.Assert(pk, IsNil)
	pk, err = GetPriKey(testPriKey)
	c.Assert(err, IsNil)
	c.Assert(pk, NotNil)
	result, err := GetPriKeyRawBytes(pk)
	c.Assert(err, IsNil)
	c.Assert(result, NotNil)
	c.Assert(result, HasLen, 32)
}

func (KeyProviderTestSuite) TestGetPeerIDs(c *C) {
	pubKeys := []string{
		"02f0b597f54b5b9bbec363426d8206ed045343afee34918137d9520d635ca7f16a",
		"023b4c7029cc9375ba8ff42f1d258eee6c492e96775cfc6d130db8fead5d3f800b",
	}
	peers, err := GetPeerIDs(pubKeys)
	c.Assert(err, IsNil)
	c.Assert(peers, NotNil)
	c.Assert(peers, HasLen, 2)
	c.Assert(peers[0].String(), Equals, "16Uiu2HAmBdJRswX94UwYj6VLhh4GeUf9X3SjBRgTqFkeEMLmfk2M")
	c.Assert(peers[1].String(), Equals, "16Uiu2HAkyR9dsFqkj1BqKw8ZHAUU2yur6ZLRJxPTiiVYP5uBMeMG")
	pubKeys1 := append(pubKeys, "helloworld")
	peers, err = GetPeerIDs(pubKeys1)
	c.Assert(err, NotNil)
	c.Assert(peers, IsNil)
}

func (KeyProviderTestSuite) TestGetPeerIDFromPubKey(c *C) {
	pID, err := GetPeerIDFromPubKey("02f0b597f54b5b9bbec363426d8206ed045343afee34918137d9520d635ca7f16a")
	c.Assert(err, IsNil)
	c.Assert(pID.String(), Equals, "16Uiu2HAmBdJRswX94UwYj6VLhh4GeUf9X3SjBRgTqFkeEMLmfk2M")
	pID1, err := GetPeerIDFromPubKey("whatever")
	c.Assert(err, NotNil)
	c.Assert(pID1.String(), Equals, "")
}

func (KeyProviderTestSuite) TestCheckKeyOnCurve(c *C) {
	_, err := CheckKeyOnCurve("aa")
	c.Assert(err, NotNil)
	_, err = CheckKeyOnCurve("02f0b597f54b5b9bbec363426d8206ed045343afee34918137d9520d635ca7f16a")
	c.Assert(err, IsNil)
}
