package tss

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	btsskeygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	maddr "github.com/multiformats/go-multiaddr"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/keygen"
	"gitlab.com/thorchain/tss/go-tss/keysign"
)

const (
	partyNum         = 4
	testFileLocation = "../test_data"
	preParamTestFile = "preParam_test.data"
)

var (
	testPubKeys = []string{
		"02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5",
		"02e010109a4594ae47c258fb5b82376f6d87b9f6d3e0921ea5dff7f5306148dee6",
		"0286424b3410de5f83c80057274cc08114cc3668639ba1788ba125899247c1f13a",
		"02658753f5e928b7bf1156f7fb13c0184390984dfdb0e4c1496d39e8806e9f5ec1",
	}
	testPriKeyArr = []string{
		"2450762c8259b4af8a6ac2b4d0d70d8a5e0f4494b87389623a72b49c36a586a7",
		"bcb3068555cc3974159c013705453c7f0363fead196e774a9309b17d2e4437d6",
		"e8b001996078897aa4a8e27d1f4605100d82492c7a6c0ed700a1b223f4c3b5ab",
		"e76f299208ee0967c7c752628448e22174bb8df4d2fef8847406e3a95bd289f4",
	}
)

func TestPackage(t *testing.T) {
	TestingT(t)
}

type FourNodeTestSuite struct {
	servers       []*TssServer
	ports         []int
	preParams     []*btsskeygen.LocalPreParams
	bootstrapPeer string
}

var _ = Suite(&FourNodeTestSuite{})

// setup four nodes for test
func (s *FourNodeTestSuite) SetUpTest(c *C) {
	common.InitLog("info", true, "four_nodes_test")
	// conversion.SetupBech32Prefix()
	s.ports = []int{
		16666, 16667, 16668, 16669,
	}
	s.bootstrapPeer = "/ip4/127.0.0.1/tcp/16666/p2p/16Uiu2HAmACG5DtqmQsHtXg4G2sLS65ttv84e7MrL4kapkjfmhxAp"
	s.preParams = getPreparams(c)
	s.servers = make([]*TssServer, partyNum)

	conf := common.TssConfig{
		KeyGenTimeout:   90 * time.Second,
		KeySignTimeout:  90 * time.Second,
		PreParamTimeout: 5 * time.Second,
		EnableMonitor:   false,
	}

	var wg sync.WaitGroup
	for i := 0; i < partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx == 0 {
				s.servers[idx] = s.getTssServer(c, idx, conf, "")
			} else {
				s.servers[idx] = s.getTssServer(c, idx, conf, s.bootstrapPeer)
			}
		}(i)

		time.Sleep(time.Second)
	}
	wg.Wait()
	for i := 0; i < partyNum; i++ {
		c.Assert(s.servers[i].Start(), IsNil)
	}
}

func hash(payload []byte) []byte {
	h := sha256.New()
	h.Write(payload)
	return h.Sum(nil)
}

// we do for both join party schemes
func (s *FourNodeTestSuite) Test4NodesTss(c *C) {
	s.doTestKeygenAndKeySign(c, false)
	time.Sleep(time.Second * 2)
	s.doTestKeygenAndKeySign(c, true)

	time.Sleep(time.Second * 2)
	s.doTestFailJoinParty(c, false)
	time.Sleep(time.Second * 2)
	s.doTestFailJoinParty(c, true)

	time.Sleep(time.Second * 2)
	s.doTestBlame(c, false)
	time.Sleep(time.Second * 2)
	s.doTestBlame(c, true)
}

func checkSignResult(c *C, keysignResult map[int]keysign.Response) {
	for i := 0; i < len(keysignResult)-1; i++ {
		currentSignatures := keysignResult[i].Signatures
		// we test with two messsages and the size of the signature should be 44
		c.Assert(currentSignatures, HasLen, 2)
		c.Assert(currentSignatures[0].S, HasLen, 44)
		currentData, err := json.Marshal(currentSignatures)
		c.Assert(err, IsNil)
		nextSignatures := keysignResult[i+1].Signatures
		nextData, err := json.Marshal(nextSignatures)
		c.Assert(err, IsNil)
		ret := bytes.Equal(currentData, nextData)
		c.Assert(ret, Equals, true)
	}
}

// generate a new key
func (s *FourNodeTestSuite) doTestKeygenAndKeySign(c *C, newJoinParty bool) {
	wg := sync.WaitGroup{}
	lock := &sync.Mutex{}
	keygenResult := make(map[int]keygen.Response)
	for i := 0; i < partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var req keygen.Request
			localPubKeys := append([]string{}, testPubKeys...)
			if newJoinParty {
				req = keygen.NewRequest(localPubKeys, 10, "0.14.0")
			} else {
				req = keygen.NewRequest(localPubKeys, 10, "0.13.0")
			}
			res, err := s.servers[idx].Keygen(req)
			c.Assert(err, IsNil)
			lock.Lock()
			defer lock.Unlock()
			keygenResult[idx] = res
		}(i)
	}
	wg.Wait()
	var poolPubKey string
	for _, item := range keygenResult {
		if len(poolPubKey) == 0 {
			poolPubKey = item.PubKey
		} else {
			c.Assert(poolPubKey, Equals, item.PubKey)
		}
	}

	keysignReqWithErr := keysign.NewRequest(poolPubKey, []string{"helloworld", "helloworld2"}, 10, testPubKeys, "0.13.0")
	if newJoinParty {
		keysignReqWithErr = keysign.NewRequest(poolPubKey, []string{"helloworld", "helloworld2"}, 10, testPubKeys, "0.14.0")
	}

	resp, err := s.servers[0].KeySign(keysignReqWithErr)
	c.Assert(err, NotNil)
	c.Assert(resp.Signatures, HasLen, 0)
	if !newJoinParty {
		keysignReqWithErr1 := keysign.NewRequest(poolPubKey, []string{hex.EncodeToString(hash([]byte("helloworld"))), hex.EncodeToString(hash([]byte("helloworld2")))}, 10, testPubKeys[:1], "0.13.0")
		resp, err = s.servers[0].KeySign(keysignReqWithErr1)
		c.Assert(err, NotNil)
		c.Assert(resp.Signatures, HasLen, 0)

	}
	if !newJoinParty {
		keysignReqWithErr2 := keysign.NewRequest(poolPubKey, []string{hex.EncodeToString(hash([]byte("helloworld"))), hex.EncodeToString(hash([]byte("helloworld2")))}, 10, nil, "0.13.0")
		resp, err = s.servers[0].KeySign(keysignReqWithErr2)
		c.Assert(err, NotNil)
		c.Assert(resp.Signatures, HasLen, 0)
	}

	keysignResult := make(map[int]keysign.Response)
	for i := 0; i < partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			localPubKeys := append([]string{}, testPubKeys...)
			var keysignReq keysign.Request
			if newJoinParty {
				keysignReq = keysign.NewRequest(poolPubKey, []string{hex.EncodeToString(hash([]byte("helloworld"))), hex.EncodeToString(hash([]byte("helloworld2")))}, 10, localPubKeys, "0.14.0")
			} else {
				keysignReq = keysign.NewRequest(poolPubKey, []string{hex.EncodeToString(hash([]byte("helloworld"))), hex.EncodeToString(hash([]byte("helloworld2")))}, 10, localPubKeys, "0.13.0")
			}
			res, err := s.servers[idx].KeySign(keysignReq)
			c.Assert(err, IsNil)
			lock.Lock()
			defer lock.Unlock()
			keysignResult[idx] = res
		}(i)
	}
	wg.Wait()
	checkSignResult(c, keysignResult)

	keysignResult1 := make(map[int]keysign.Response)
	for i := 0; i < partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var keysignReq keysign.Request
			if newJoinParty {
				keysignReq = keysign.NewRequest(poolPubKey, []string{hex.EncodeToString(hash([]byte("helloworld"))), hex.EncodeToString(hash([]byte("helloworld2")))}, 10, nil, "0.14.0")
			} else {
				keysignReq = keysign.NewRequest(poolPubKey, []string{hex.EncodeToString(hash([]byte("helloworld"))), hex.EncodeToString(hash([]byte("helloworld2")))}, 10, testPubKeys[:3], "0.13.0")
			}
			res, err := s.servers[idx].KeySign(keysignReq)
			c.Assert(err, IsNil)
			lock.Lock()
			defer lock.Unlock()
			keysignResult1[idx] = res
		}(i)
	}
	wg.Wait()
	checkSignResult(c, keysignResult1)
}

func (s *FourNodeTestSuite) doTestFailJoinParty(c *C, newJoinParty bool) {
	// JoinParty should fail if there is a node that suppose to be in the keygen , but we didn't send request in
	wg := sync.WaitGroup{}
	lock := &sync.Mutex{}
	keygenResult := make(map[int]keygen.Response)
	// here we skip the first node
	for i := 1; i < partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var req keygen.Request
			if newJoinParty {
				req = keygen.NewRequest(testPubKeys, 10, "0.14.0")
			} else {
				req = keygen.NewRequest(testPubKeys, 10, "0.13.0")
			}
			res, err := s.servers[idx].Keygen(req)
			c.Assert(err, IsNil)
			lock.Lock()
			defer lock.Unlock()
			keygenResult[idx] = res
		}(i)
	}

	wg.Wait()
	c.Logf("result:%+v", keygenResult)
	for _, item := range keygenResult {
		c.Assert(item.PubKey, Equals, "")
		c.Assert(item.Status, Equals, common.Fail)
		var expectedFailNode string
		if newJoinParty {
			c.Assert(item.Blame.BlameNodes, HasLen, 2)
			expectedFailNode := []string{"02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5", "0286424b3410de5f83c80057274cc08114cc3668639ba1788ba125899247c1f13a"}
			c.Assert(item.Blame.BlameNodes[0].Pubkey, Equals, expectedFailNode[0])
			c.Assert(item.Blame.BlameNodes[1].Pubkey, Equals, expectedFailNode[1])
		} else {
			expectedFailNode = "02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5"
			c.Assert(item.Blame.BlameNodes[0].Pubkey, Equals, expectedFailNode)
		}
	}
}

func (s *FourNodeTestSuite) doTestBlame(c *C, newJoinParty bool) {
	expectedFailNode := "02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5"
	var req keygen.Request
	if newJoinParty {
		req = keygen.NewRequest(testPubKeys, 10, "0.14.0")
	} else {
		req = keygen.NewRequest(testPubKeys, 10, "0.13.0")
	}
	wg := sync.WaitGroup{}
	lock := &sync.Mutex{}
	keygenResult := make(map[int]keygen.Response)
	for i := 0; i < partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := s.servers[idx].Keygen(req)
			c.Assert(err, NotNil)
			lock.Lock()
			defer lock.Unlock()
			keygenResult[idx] = res
		}(i)
	}
	// if we shutdown one server during keygen , he should be blamed

	time.Sleep(time.Millisecond * 100)
	s.servers[0].Stop()
	defer func() {
		conf := common.TssConfig{
			KeyGenTimeout:   60 * time.Second,
			KeySignTimeout:  60 * time.Second,
			PreParamTimeout: 5 * time.Second,
		}
		s.servers[0] = s.getTssServer(c, 0, conf, s.bootstrapPeer)
		c.Assert(s.servers[0].Start(), IsNil)
		c.Log("we start the first server again")
	}()
	wg.Wait()
	c.Logf("result:%+v", keygenResult)
	for idx, item := range keygenResult {
		if idx == 0 {
			continue
		}
		c.Assert(item.PubKey, Equals, "")
		c.Assert(item.Status, Equals, common.Fail)
		c.Assert(item.Blame.BlameNodes, HasLen, 1)
		c.Assert(item.Blame.BlameNodes[0].Pubkey, Equals, expectedFailNode)
	}
}

func (s *FourNodeTestSuite) TearDownTest(c *C) {
	// give a second before we shutdown the network
	time.Sleep(time.Second)
	for i := 0; i < partyNum; i++ {
		s.servers[i].Stop()
	}
	for i := 0; i < partyNum; i++ {
		tempFilePath := path.Join(os.TempDir(), "4nodes_test", strconv.Itoa(i))
		os.RemoveAll(tempFilePath)

	}
}

func (s *FourNodeTestSuite) getTssServer(c *C, index int, conf common.TssConfig, bootstrap string) *TssServer {
	priKey, err := conversion.GetPriKey(testPriKeyArr[index])
	c.Assert(err, IsNil)
	baseHome := path.Join(os.TempDir(), "4nodes_test", strconv.Itoa(index))
	if _, err := os.Stat(baseHome); os.IsNotExist(err) {
		err := os.MkdirAll(baseHome, os.ModePerm)
		c.Assert(err, IsNil)
	}
	var peerIDs []maddr.Multiaddr
	if len(bootstrap) > 0 {
		multiAddr, err := maddr.NewMultiaddr(bootstrap)
		c.Assert(err, IsNil)
		peerIDs = []maddr.Multiaddr{multiAddr}
	} else {
		peerIDs = nil
	}
	instance, err := NewTss(peerIDs, s.ports[index], priKey, "Asgard", baseHome, conf, s.preParams[index], "")
	c.Assert(err, IsNil)
	return instance
}

func getPreparams(c *C) []*btsskeygen.LocalPreParams {
	var preParamArray []*btsskeygen.LocalPreParams
	buf, err := ioutil.ReadFile(path.Join(testFileLocation, preParamTestFile))
	c.Assert(err, IsNil)
	preParamsStr := strings.Split(string(buf), "\n")
	for _, item := range preParamsStr {
		var preParam btsskeygen.LocalPreParams
		val, err := hex.DecodeString(item)
		c.Assert(err, IsNil)
		c.Assert(json.Unmarshal(val, &preParam), IsNil)
		preParamArray = append(preParamArray, &preParam)
	}
	return preParamArray
}
