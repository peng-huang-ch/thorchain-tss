package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/keygen"
)

func TestPackage(t *testing.T) { TestingT(t) }

type TssHttpServerTestSuite struct {
}

var _ = Suite(&TssHttpServerTestSuite{})

func (TssHttpServerTestSuite) TestNewTssHttpServer(c *C) {
	tssServer := &MockTssServer{}
	s := NewTssHttpServer("127.0.0.1:8080", tssServer)
	c.Assert(s, NotNil)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := s.Start()
		c.Assert(err, IsNil)
	}()
	time.Sleep(time.Second)
	c.Assert(s.Stop(), IsNil)
	tssServer.failToStart = true
	c.Assert(s.Start(), NotNil)
}

func (TssHttpServerTestSuite) TestPingHandler(c *C) {
	tssServer := &MockTssServer{}
	s := NewTssHttpServer("127.0.0.1:8080", tssServer)
	c.Assert(s, NotNil)
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	res := httptest.NewRecorder()
	s.pingHandler(res, req)
	c.Assert(res.Code, Equals, http.StatusOK)
}

func (TssHttpServerTestSuite) TestGetP2pIDHandler(c *C) {
	tssServer := &MockTssServer{}
	s := NewTssHttpServer("127.0.0.1:8080", tssServer)
	c.Assert(s, NotNil)
	req := httptest.NewRequest(http.MethodGet, "/p2pid", nil)
	res := httptest.NewRecorder()
	s.getP2pIDHandler(res, req)
	c.Assert(res.Code, Equals, http.StatusOK)
}

func (TssHttpServerTestSuite) TestKeygenHandler(c *C) {
	normalKeygenRequest := `{"keys":["02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5", "02e010109a4594ae47c258fb5b82376f6d87b9f6d3e0921ea5dff7f5306148dee6", "0286424b3410de5f83c80057274cc08114cc3668639ba1788ba125899247c1f13a", "02658753f5e928b7bf1156f7fb13c0184390984dfdb0e4c1496d39e8806e9f5ec1"]}`
	testCases := []struct {
		name          string
		reqProvider   func() *http.Request
		setter        func(s *MockTssServer)
		resultChecker func(c *C, w *httptest.ResponseRecorder)
	}{
		{
			name: "method get should return status method not allowed",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/keygen", nil)
			},
			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusMethodNotAllowed)
			},
		},
		{
			name: "nil request body should return status bad request",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/keygen", nil)
			},
			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusBadRequest)
			},
		},
		{
			name: "fail to keygen should return status internal server error",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/keygen",
					bytes.NewBufferString(normalKeygenRequest))
			},
			setter: func(s *MockTssServer) {
				s.failToKeyGen = true
			},
			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusOK)
			},
		},
		{
			name: "normal",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/keygen",
					bytes.NewBufferString(normalKeygenRequest))
			},

			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusOK)
				var resp keygen.Response
				c.Assert(json.Unmarshal(w.Body.Bytes(), &resp), IsNil)
			},
		},
	}
	for _, tc := range testCases {
		c.Log(tc.name)
		tssServer := &MockTssServer{}
		s := NewTssHttpServer("127.0.0.1:8080", tssServer)
		c.Assert(s, NotNil)
		if tc.setter != nil {
			tc.setter(tssServer)
		}
		req := tc.reqProvider()
		res := httptest.NewRecorder()
		s.keygenHandler(res, req)
		tc.resultChecker(c, res)
	}
}

func (TssHttpServerTestSuite) TestKeysignHandler(c *C) {
	var normalKeySignRequest string = `{
    "pool_pub_key": "02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5",
    "message": "helloworld",
    "signer_pub_keys": [
        "02db6fb8eb4c7b390bd39d13f2478c02b3af395d0ce9a7c2b0dec6b2e626a2a6b5",
        "02e010109a4594ae47c258fb5b82376f6d87b9f6d3e0921ea5dff7f5306148dee6",
        "0286424b3410de5f83c80057274cc08114cc3668639ba1788ba125899247c1f13a",
        "02658753f5e928b7bf1156f7fb13c0184390984dfdb0e4c1496d39e8806e9f5ec1"
    ]
}`
	testCases := []struct {
		name          string
		reqProvider   func() *http.Request
		setter        func(s *MockTssServer)
		resultChecker func(c *C, w *httptest.ResponseRecorder)
	}{
		{
			name: "method get should return status method not allowed",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/keysign", nil)
			},
			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusMethodNotAllowed)
			},
		},
		{
			name: "nil request body should return status bad request",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/keysign", nil)
			},
			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusBadRequest)
			},
		},
		{
			name: "fail to keygen should return status internal server error",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/keysign",
					bytes.NewBufferString(normalKeySignRequest))
			},
			setter: func(s *MockTssServer) {
				s.failToKeySign = true
			},
			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusInternalServerError)
			},
		},
		{
			name: "normal",
			reqProvider: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/keysign",
					bytes.NewBufferString(normalKeySignRequest))
			},

			resultChecker: func(c *C, w *httptest.ResponseRecorder) {
				c.Assert(w.Code, Equals, http.StatusOK)
				var resp keygen.Response
				c.Assert(json.Unmarshal(w.Body.Bytes(), &resp), IsNil)
			},
		},
	}
	for _, tc := range testCases {
		c.Log(tc.name)
		tssServer := &MockTssServer{}
		s := NewTssHttpServer("127.0.0.1:8080", tssServer)
		c.Assert(s, NotNil)
		if tc.setter != nil {
			tc.setter(tssServer)
		}
		req := tc.reqProvider()
		res := httptest.NewRecorder()
		s.keySignHandler(res, req)
		tc.resultChecker(c, res)
	}
}
