package common

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	btsskeygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	btss "github.com/binance-chain/tss-lib/tss"
	coskey "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types/bech32/legacybech32"
	tcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/blame"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/p2p"
)

var (
	testBlamePrivKey = "bcb3068555cc3974159c013705453c7f0363fead196e774a9309b17d2e4437d6"
	testSenderPubKey = "02e010109a4594ae47c258fb5b82376f6d87b9f6d3e0921ea5dff7f5306148dee6"
	testPubKeys      = [...]string{"02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5", "02e010109a4594ae47c258fb5b82376f6d87b9f6d3e0921ea5dff7f5306148dee6", "0286424b3410de5f83c80057274cc08114cc3668639ba1788ba125899247c1f13a", "02658753f5e928b7bf1156f7fb13c0184390984dfdb0e4c1496d39e8806e9f5ec1"}
	testBlamePubKeys = []string{"02c7409d7ffdc35374dbe7bc2b83335543b1b7f3cd859642fd05882683f2de8799", "02e010109a4594ae47c258fb5b82376f6d87b9f6d3e0921ea5dff7f5306148dee6", "023b59b72da5ef37406ed8e703be2ef3385da52128f4d157fa86fae72bf4e433c0", "028f74b43c88da8648f0b0affd9ee45d27f73b070c86264d548c8facd5bc94b528", "0278079b1af3e8aba8e71e93f0ebdf7cc85da35c8c0d780ffcb11287a72596811d", "03e5012e077f1a9fd4364db580963aaf89fd26fcd06d53eb8e9344a824b50338fb", "03b5bda536d16745f7a0b822e860fb634301b6662e9f6e4b37ac9db2fe479f09c3", "03c2dbed52eac485309a491c72b21a047d5174806d2a53ba6773bc77a060553444", "0210edfd0d3f0ab540d5ebe0b201d710d8db858d73bd003a6ec90775507273b650", "02e10fac9266e070f7d6a9107a7e639016c60d59c0e3a1df7e0f6a25a6945cf821"}
)

func TestPackage(t *testing.T) { TestingT(t) }

type TssTestSuite struct {
	privKey tcrypto.PrivKey
}

var _ = Suite(&TssTestSuite{})

func (t *TssTestSuite) SetUpSuite(c *C) {
	InitLog("info", true, "tss_common_test")
	priHexBytes, err := hex.DecodeString(testBlamePrivKey)
	c.Assert(err, IsNil)
	rawBytes, err := hex.DecodeString(string(priHexBytes))
	c.Assert(err, IsNil)
	var priKey secp256k1.PrivKey
	priKey = rawBytes[:32]
	t.privKey = priKey
}

func (t *TssTestSuite) TestGetThreshold(c *C) {
	_, err := conversion.GetThreshold(-2)
	c.Assert(err, NotNil)
	output, err := conversion.GetThreshold(4)
	c.Assert(err, IsNil)
	c.Assert(output, Equals, 2)
	output, err = conversion.GetThreshold(9)
	c.Assert(err, IsNil)
	c.Assert(output, Equals, 5)
	output, err = conversion.GetThreshold(10)
	c.Assert(err, IsNil)
	c.Assert(output, Equals, 6)
	output, err = conversion.GetThreshold(99)
	c.Assert(err, IsNil)
	c.Assert(output, Equals, 65)
}

func (t *TssTestSuite) TestMsgToHashInt(c *C) {
	input := []byte("whatever")
	result, err := MsgToHashInt(input)
	c.Assert(err, IsNil)
	c.Assert(result, NotNil)
}

func (t *TssTestSuite) TestContains(c *C) {
	t1 := btss.PartyID{
		Index: 1,
	}
	ret := Contains(nil, &t1)
	c.Assert(ret, Equals, false)

	t2 := btss.PartyID{
		Index: 2,
	}
	t3 := btss.PartyID{
		Index: 3,
	}
	testParties := []*btss.PartyID{&t2, &t3}
	ret = Contains(testParties, &t1)
	c.Assert(ret, Equals, false)
	testParties = append(testParties, &t1)
	ret = Contains(testParties, &t1)
	c.Assert(ret, Equals, true)
	ret = Contains(testParties, nil)
	c.Assert(ret, Equals, false)
}

func (t *TssTestSuite) TestTssProcessOutCh(c *C) {
	conf := TssConfig{}
	localTestPubKeys := make([]string, len(testPubKeys))
	copy(localTestPubKeys, testPubKeys[:])
	partiesID, localPartyID, err := conversion.GetParties(localTestPubKeys, testPubKeys[0])
	c.Assert(err, IsNil)
	messageRouting := btss.MessageRouting{
		From:                    localPartyID,
		To:                      partiesID[3:],
		IsBroadcast:             true,
		IsToOldCommittee:        false,
		IsToOldAndNewCommittees: false,
	}
	testFill := []byte("TEST")
	testContent := &btsskeygen.KGRound1Message{
		Commitment: testFill,
	}
	msg := btss.NewMessageWrapper(messageRouting, testContent)
	tssMsg := btss.NewMessage(messageRouting, testContent, msg)
	tssCommonStruct := NewTssCommon("", nil, conf, "test", t.privKey, 1)
	err = tssCommonStruct.ProcessOutCh(tssMsg, messages.TSSKeyGenMsg)
	c.Assert(err, IsNil)
}

func fabricateTssMsg(c *C, privKey tcrypto.PrivKey, partyID *btss.PartyID, roundInfo, msg, msgID string, msgType messages.THORChainTSSMessageType) (*messages.WrappedMessage, []byte) {
	routingInfo := btss.MessageRouting{
		From:                    partyID,
		To:                      nil,
		IsBroadcast:             true,
		IsToOldCommittee:        false,
		IsToOldAndNewCommittees: false,
	}

	bulkMsg := NewBulkWireMsg([]byte(msg), "tester", &routingInfo)
	buf, err := json.Marshal([]BulkWireMsg{bulkMsg})
	var dataForSign bytes.Buffer
	dataForSign.Write(buf)
	dataForSign.WriteString(msgID)
	sig, err := privKey.Sign(dataForSign.Bytes())
	c.Assert(err, IsNil)
	wiredMessage := messages.WireMessage{
		Routing:   &routingInfo,
		RoundInfo: roundInfo,
		Message:   buf,
		Sig:       sig,
	}

	marshaledMsg, err := json.Marshal(wiredMessage)
	c.Assert(err, IsNil)
	wrappedMsg := messages.WrappedMessage{
		MessageType: msgType,
		Payload:     marshaledMsg,
	}
	return &wrappedMsg, sig
}

func fabricateVerMsg(c *C, hash, hashKey string) *messages.WrappedMessage {
	broadcastConfirmMsg := &messages.BroadcastConfirmMessage{
		P2PID: "",
		Key:   hashKey,
		Hash:  hash,
	}
	marshaledMsg, err := json.Marshal(broadcastConfirmMsg)
	c.Assert(err, IsNil)
	wrappedMsg := messages.WrappedMessage{
		MessageType: messages.TSSKeyGenVerMsg,
		Payload:     marshaledMsg,
	}
	return &wrappedMsg
}

func (t *TssTestSuite) testVerMsgDuplication(c *C, privKey tcrypto.PrivKey, tssCommonStruct *TssCommon, senderID *btss.PartyID, partiesID []*btss.PartyID) {
	testMsg := "testVerMsgDuplication"
	roundInfo := "round testVerMsgDuplication"
	tssCommonStruct.msgID = "123"
	msgKey := fmt.Sprintf("%s-%s", senderID.Id, roundInfo)
	wrappedMsg, _ := fabricateTssMsg(c, privKey, senderID, roundInfo, testMsg, tssCommonStruct.msgID, messages.TSSKeyGenMsg)
	err := tssCommonStruct.ProcessOneMessage(wrappedMsg, tssCommonStruct.PartyIDtoP2PID[partiesID[1].Id].String())
	c.Assert(err, IsNil)
	localItem := tssCommonStruct.TryGetLocalCacheItem(msgKey)
	c.Assert(localItem.ConfirmedList, HasLen, 1)
	err = tssCommonStruct.ProcessOneMessage(wrappedMsg, tssCommonStruct.PartyIDtoP2PID[partiesID[1].Id].String())
	c.Assert(err, IsNil)
	c.Assert(localItem.ConfirmedList, HasLen, 1)
}

func setupProcessVerMsgEnv(c *C, privKey tcrypto.PrivKey, keyPool []string, partyNum int) (*TssCommon, []*btss.PartyID, []*btss.PartyID) {
	conf := TssConfig{}
	tssCommonStruct := NewTssCommon("", nil, conf, "test", privKey, 1)
	localTestPubKeys := make([]string, partyNum)
	copy(localTestPubKeys, keyPool[:partyNum])
	// for the test, we choose the first pubic key as the test instance public key
	partiesID, localPartyID, err := conversion.GetParties(localTestPubKeys, keyPool[0])
	c.Assert(err, IsNil)
	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	conversion.SetupIDMaps(partyIDMap, tssCommonStruct.PartyIDtoP2PID)
	ctx := btss.NewPeerContext(partiesID)
	params := btss.NewParameters(ctx, localPartyID, len(partiesID), 2)
	outCh := make(chan btss.Message, len(partiesID))
	endCh := make(chan btsskeygen.LocalPartySaveData, len(partiesID))
	keyGenParty := btsskeygen.NewLocalParty(params, outCh, endCh)
	partyMap := new(sync.Map)
	partyMap.Store("tester", keyGenParty)
	tssCommonStruct.SetPartyInfo(&PartyInfo{
		Threshold:  1,
		PartyMap:   partyMap,
		PartyIDMap: partyIDMap,
	})
	err = conversion.SetupIDMaps(partyIDMap, tssCommonStruct.blameMgr.PartyIDtoP2PID)
	c.Assert(err, IsNil)
	tssCommonStruct.SetLocalPeerID("fakeID")
	err = conversion.SetupIDMaps(partyIDMap, tssCommonStruct.PartyIDtoP2PID)
	c.Assert(err, IsNil)
	tssCommonStruct.blameMgr.SetPartyInfo(partyMap, partyIDMap)
	peerPartiesID := append(partiesID[:localPartyID.Index], partiesID[localPartyID.Index+1:]...)
	tssCommonStruct.P2PPeersLock.Lock()
	tssCommonStruct.P2PPeers = conversion.GetPeersID(tssCommonStruct.PartyIDtoP2PID, tssCommonStruct.GetLocalPeerID())
	tssCommonStruct.P2PPeersLock.Unlock()
	return tssCommonStruct, peerPartiesID, partiesID
}

func (t *TssTestSuite) testDropMsgOwner(c *C, privKey tcrypto.PrivKey, tssCommonStruct *TssCommon, senderID *btss.PartyID, peerPartiesID []*btss.PartyID) {
	testMsg := "testDropMsgOwner"
	roundInfo := "round testDropMsgOwner"
	msgHash, err := conversion.BytesToHashString([]byte(testMsg))
	c.Assert(err, IsNil)
	msgKey := fmt.Sprintf("%s-%s", senderID.Id, roundInfo)
	senderMsg, expectedSignature := fabricateTssMsg(c, privKey, senderID, roundInfo, testMsg, "123", messages.TSSKeyGenMsg)

	senderPeer, err := conversion.GetPeerIDFromPartyID(senderID)
	c.Assert(err, IsNil)
	// you can pass any p2pID in Tss message
	err = tssCommonStruct.ProcessOneMessage(senderMsg, senderPeer.String())
	c.Assert(err, IsNil)
	localItem := tssCommonStruct.TryGetLocalCacheItem(msgKey)
	c.Assert(localItem.ConfirmedList, HasLen, 1)
	wrappedVerMsg := fabricateVerMsg(c, msgHash, msgKey)
	err = tssCommonStruct.ProcessOneMessage(wrappedVerMsg, senderPeer.String())
	c.Assert(err, Equals, blame.ErrHashCheck)
	// since we re-use the tsscommon, so we may have more than one signature
	var blameSig [][]byte
	blameNodes := tssCommonStruct.blameMgr.GetBlame().BlameNodes
	for _, el := range blameNodes {
		blameSig = append(blameSig, el.BlameSignature)
	}
	found := false
	for _, el := range blameSig {
		if bytes.Equal(el, expectedSignature) {
			found = true
			break
		}
	}
	c.Assert(found, Equals, true)
}

func (t *TssTestSuite) testProcessControlMsg(c *C, tssCommonStruct *TssCommon) {
	controlMsg := messages.TssControl{
		ReqHash:     "testHash",
		ReqKey:      "testKey",
		RequestType: messages.TSSKeyGenMsg,
		Msg:         nil,
	}
	payload, err := json.Marshal(controlMsg)
	c.Assert(err, IsNil)
	wrappedMsg := messages.WrappedMessage{
		MessageType: messages.TSSControlMsg,
		Payload:     payload,
	}

	err = tssCommonStruct.ProcessOneMessage(&wrappedMsg, "1")
	c.Assert(err, NotNil)
	err = tssCommonStruct.ProcessOneMessage(&wrappedMsg, "16Uiu2HAmACG5DtqmQsHtXg4G2sLS65ttv84e7MrL4kapkjfmhxAp")
	c.Assert(err, IsNil)
	tssCommonStruct.blameMgr.GetShareMgr().Set("testHash")

	msg := messages.WireMessage{
		Routing:   nil,
		RoundInfo: "",
		Message:   []byte("test"),
		Sig:       []byte("test"),
	}
	controlMsg = messages.TssControl{
		ReqHash:     "testHash",
		ReqKey:      "testKey",
		RequestType: messages.TSSKeyGenMsg,
		Msg:         &msg,
	}
	payload, err = json.Marshal(controlMsg)
	c.Assert(err, IsNil)
	wrappedMsg = messages.WrappedMessage{
		MessageType: messages.TSSControlMsg,
		Payload:     payload,
	}

	err = tssCommonStruct.ProcessOneMessage(&wrappedMsg, "16Uiu2HAmACG5DtqmQsHtXg4G2sLS65ttv84e7MrL4kapkjfmhxAp")
	c.Assert(err, ErrorMatches, "invalid wireMsg")
}

func (t *TssTestSuite) testProcessTaskDone(c *C, tssCommonStruct *TssCommon) {
	taskDone := messages.TssTaskNotifier{TaskDone: true}
	marshaledMsg, err := json.Marshal(taskDone)
	c.Assert(err, IsNil)
	wrappedMsg := messages.WrappedMessage{
		MessageType: messages.TSSTaskDone,
		Payload:     marshaledMsg,
	}
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = tssCommonStruct.ProcessOneMessage(&wrappedMsg, "1")
		c.Assert(err, IsNil)
		err = tssCommonStruct.ProcessOneMessage(&wrappedMsg, "2")
		c.Assert(err, IsNil)
		err = tssCommonStruct.ProcessOneMessage(&wrappedMsg, "3")
		c.Assert(err, IsNil)
	}()
	select {
	case <-tssCommonStruct.taskDone:
		return
	case <-time.After(time.Millisecond * 20):
		c.Fail()
	}
	wg.Done()
}

func (t *TssTestSuite) testVerMsgAndUpdateFromPeer(c *C, tssCommonStruct *TssCommon, senderID *btss.PartyID, partiesID []*btss.PartyID) {
	testMsg := "testVerMsgAndUpdate2"
	roundInfo := "round testVerMsgAndUpdate2"
	msgHash, err := conversion.BytesToHashString([]byte(testMsg))
	c.Assert(err, IsNil)
	msgKey := fmt.Sprintf("%s-%s", senderID.Id, roundInfo)
	// we send the verify message from the the same sender, Tss should only accept the first verify message
	wrappedVerMsg := fabricateVerMsg(c, msgHash, msgKey)
	err = tssCommonStruct.ProcessOneMessage(wrappedVerMsg, tssCommonStruct.PartyIDtoP2PID[partiesID[1].Id].String())
	c.Assert(err, IsNil)
	localItem := tssCommonStruct.TryGetLocalCacheItem(msgKey)
	c.Assert(localItem.ConfirmedList, HasLen, 1)
	err = tssCommonStruct.ProcessOneMessage(wrappedVerMsg, tssCommonStruct.PartyIDtoP2PID[partiesID[1].Id].String())
	c.Assert(err, IsNil)
	localItem = tssCommonStruct.TryGetLocalCacheItem(msgKey)
	c.Assert(localItem.ConfirmedList, HasLen, 1)
}

func (t *TssTestSuite) testVerMsgAndUpdate(c *C, tssCommonStruct *TssCommon, senderID *btss.PartyID, partiesID []*btss.PartyID) {
	testMsg := "testVerMsgAndUpdate"
	roundInfo := "round testVerMsgAndUpdate"
	msgKey := fmt.Sprintf("%s-%s", senderID.Id, roundInfo)
	wrappedMsg, _ := fabricateTssMsg(c, t.privKey, senderID, roundInfo, testMsg, "123", messages.TSSKeyGenMsg)
	// you can pass any p2pID in Tss message
	err := tssCommonStruct.ProcessOneMessage(wrappedMsg, tssCommonStruct.PartyIDtoP2PID[senderID.Id].String())
	c.Assert(err, IsNil)
	localItem := tssCommonStruct.TryGetLocalCacheItem(msgKey)
	c.Assert(localItem.ConfirmedList, HasLen, 1)

	routingInfo := btss.MessageRouting{
		From:                    senderID,
		To:                      nil,
		IsBroadcast:             true,
		IsToOldCommittee:        false,
		IsToOldAndNewCommittees: false,
	}

	bulkMsg := NewBulkWireMsg([]byte(testMsg), "tester", &routingInfo)
	buf, err := json.Marshal([]BulkWireMsg{bulkMsg})
	c.Assert(err, IsNil)
	msgHash, err := conversion.BytesToHashString(buf)
	c.Assert(err, IsNil)
	// we send the verify message from the the same sender, Tss should only accept the first verify message
	wrappedVerMsg := fabricateVerMsg(c, msgHash, msgKey)

	err = tssCommonStruct.ProcessOneMessage(wrappedVerMsg, tssCommonStruct.PartyIDtoP2PID[partiesID[1].Id].String())
	c.Assert(err, NotNil)
	// workaround: when we hit this error, in this test, it indicates we accept the share.
	if !strings.Contains(err.Error(), "fail to update the message to local party: proto:") {
		c.Fatalf("error \"%v\" did not match the expected one", err.Error())
	}
}

func findSender(arr []*btss.PartyID) *btss.PartyID {
	for _, el := range arr {
		pk := coskey.PubKey{
			Key: el.GetKey()[:],
		}
		out, _ := sdk.MarshalPubKey(sdk.AccPK, &pk)
		if out == testSenderPubKey {
			return el
		}
	}
	return nil
}

// TestProcessVerMessage is the tests for processing the verified message
func (t *TssTestSuite) TestProcessVerMessage(c *C) {
	tssCommonStruct, peerPartiesID, partiesID := setupProcessVerMsgEnv(c, t.privKey, testBlamePubKeys, 4)
	sender := findSender(partiesID)
	t.testVerMsgDuplication(c, t.privKey, tssCommonStruct, sender, peerPartiesID)
	t.testVerMsgAndUpdateFromPeer(c, tssCommonStruct, sender, partiesID)
	t.testDropMsgOwner(c, t.privKey, tssCommonStruct, sender, peerPartiesID)
	t.testVerMsgAndUpdate(c, tssCommonStruct, sender, partiesID)
	t.testProcessControlMsg(c, tssCommonStruct)
	t.testProcessTaskDone(c, tssCommonStruct)
}

func (t *TssTestSuite) TestTssCommon(c *C) {
	pk, err := sdk.UnmarshalPubKey(sdk.AccPK, "02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5")
	c.Assert(err, IsNil)
	peerID, err := conversion.GetPeerIDFromSecp256PubKey(pk.Bytes())
	c.Assert(err, IsNil)
	broadcastChannel := make(chan *messages.BroadcastMsgChan)
	sk := secp256k1.GenPrivKey()
	tssCommon := NewTssCommon(peerID.String(), broadcastChannel, TssConfig{}, "message-id", sk, 1)
	c.Assert(tssCommon, NotNil)
	stopchan := make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		tssCommon.ProcessInboundMessages(stopchan, &wg)
	}()
	bi, err := MsgToHashInt([]byte("whatever"))
	c.Assert(err, IsNil)
	wrapMsg, _ := fabricateTssMsg(c, sk, btss.NewPartyID("1,", "test", bi), "roundInfo", "message", "123", messages.TSSKeyGenMsg)
	buf, err := json.Marshal(wrapMsg)
	c.Assert(err, IsNil)
	pMsg := &p2p.Message{
		PeerID:  peerID,
		Payload: buf,
	}

	tssCommon.partyInfo = &PartyInfo{
		PartyMap:   nil,
		PartyIDMap: make(map[string]*btss.PartyID),
	}
	tssCommon.TssMsg <- pMsg
	close(stopchan)
	wg.Wait()
}

func (t *TssTestSuite) TestProcessInvalidMsgBlame(c *C) {
	tssCommonStruct, peerPartiesID, partiesID := setupProcessVerMsgEnv(c, t.privKey, testBlamePubKeys, 4)
	sender := findSender(partiesID)

	testMsg := "testVerMsgDuplication"
	roundInfo := "round testMessage"
	tssCommonStruct.msgID = "123"
	wrappedMsg, _ := fabricateTssMsg(c, t.privKey, sender, roundInfo, testMsg, tssCommonStruct.msgID, messages.TSSKeyGenMsg)

	var wiredMsg messages.WireMessage
	err := json.Unmarshal(wrappedMsg.Payload, &wiredMsg)
	c.Assert(err, IsNil)
	culprits := peerPartiesID[:3]
	for _, el := range culprits[:2] {
		key := fmt.Sprintf("%s-%s", el.Id, roundInfo)
		tssCommonStruct.blameMgr.GetRoundMgr().Set(key, &wiredMsg)
	}

	fakeErr := btss.NewError(errors.New("test error"), "test task", 1, nil, culprits...)
	tssCommonStruct.processInvalidMsgBlame(wiredMsg.RoundInfo, blame.RoundInfo{RoundMsg: roundInfo}, fakeErr)
	blameResult := tssCommonStruct.GetBlameMgr().GetBlame()
	c.Assert(blameResult.BlameNodes, HasLen, 3)

	routingInfo := btss.MessageRouting{
		From:                    sender,
		To:                      nil,
		IsBroadcast:             true,
		IsToOldCommittee:        false,
		IsToOldAndNewCommittees: false,
	}
	bulkMsg := NewBulkWireMsg([]byte(testMsg), "tester", &routingInfo)
	buf, err := json.Marshal([]BulkWireMsg{bulkMsg})
	c.Assert(err, IsNil)

	for _, el := range blameResult.BlameNodes[:2] {
		c.Assert(el.BlameData, DeepEquals, []byte(buf))
	}
	// for the last one, since we do not store the msg before hand, it should return no record of this party
	c.Assert(blameResult.BlameNodes[2].BlameData, HasLen, 0)
}
