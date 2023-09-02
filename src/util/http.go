package util

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/klauspost/compress/gzhttp"
	"github.com/teambition/gear"
)

func init() {
	userAgent = fmt.Sprintf("Go/%v yiwen.ai", runtime.Version())
}

var userAgent string

var externalTr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 15 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   20,
	IdleConnTimeout:       25 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 10 * time.Second,
	ResponseHeaderTimeout: 15 * time.Second,
}

var ExternalHTTPClient = &http.Client{
	Transport: gzhttp.Transport(externalTr),
	Timeout:   time.Second * 15,
}

var internalTr = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 15 * time.Second,
	}).DialContext,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   100,
	IdleConnTimeout:       25 * time.Second,
	TLSHandshakeTimeout:   8 * time.Second,
	ExpectContinueTimeout: 9 * time.Second,
	ResponseHeaderTimeout: 10 * time.Second,
}

var HTTPClient = &http.Client{
	Transport: gzhttp.Transport(internalTr),
	Timeout:   time.Second * 5,
}

type ContextHTTPHeader http.Header

func RequestJSON(ctx context.Context, cli *http.Client, method, api string, input, output any) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var err error
	var body io.Reader
	if input != nil {
		data, ok := input.([]byte)
		if !ok {
			if data, err = json.Marshal(input); err != nil {
				return gear.ErrBadRequest.From(err)
			}
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, api, body)
	if err != nil {
		return gear.ErrBadRequest.From(err)
	}

	req.Header.Set(gear.HeaderUserAgent, userAgent)
	req.Header.Set(gear.HeaderAccept, gear.MIMEApplicationJSON)
	if input != nil {
		req.Header.Set(gear.HeaderContentType, gear.MIMEApplicationJSON)
	}

	if header := gear.CtxValue[ContextHTTPHeader](ctx); header != nil {
		CopyHeader(req.Header, http.Header(*header))
	}

	rid := req.Header.Get(gear.HeaderXRequestID)
	resp, err := cli.Do(req)
	if err != nil {
		if err.(*url.Error).Unwrap() == context.Canceled {
			return gear.ErrClientClosedRequest
		}

		return gear.ErrInternalServerError.From(err)
	}

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 206 || err != nil {
		er := gear.Err.WithCode(resp.StatusCode).WithMsgf("RequestJSON failed, url: %q, rid: %s, code: %d, error: %v",
			api, rid, resp.StatusCode, err)
		er.Data = string(data)
		return er
	}

	if err = json.Unmarshal(data, output); err != nil {
		er := gear.ErrInternalServerError.WithMsgf("RequestJSON failed, url: %q, rid: %s, code: %d, error: %v",
			api, rid, resp.StatusCode, err)
		er.Data = string(data)
		return er
	}
	return nil
}

func RequestCBOR(ctx context.Context, cli *http.Client, method, api string, input, output any) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	var err error
	var body io.Reader
	if input != nil {
		data, ok := input.([]byte)
		if !ok {
			if data, err = cbor.Marshal(input); err != nil {
				return gear.ErrBadRequest.From(err)
			}
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, api, body)
	if err != nil {
		return gear.ErrBadRequest.From(err)
	}

	req.Header.Set(gear.HeaderUserAgent, userAgent)
	req.Header.Set(gear.HeaderAccept, gear.MIMEApplicationCBOR)
	if input != nil {
		req.Header.Set(gear.HeaderContentType, gear.MIMEApplicationCBOR)
	}

	if header := gear.CtxValue[ContextHTTPHeader](ctx); header != nil {
		CopyHeader(req.Header, http.Header(*header))
	}

	rid := req.Header.Get(gear.HeaderXRequestID)
	resp, err := cli.Do(req)
	if err != nil {
		if err.(*url.Error).Unwrap() == context.Canceled {
			return gear.ErrClientClosedRequest
		}

		return gear.ErrInternalServerError.From(err)
	}

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 206 || err != nil {
		str, e := cbor.Diagnose(data)
		if e != nil {
			str = string(data)
		}
		er := gear.Err.WithCode(resp.StatusCode).WithMsgf("RequestCBOR failed, url: %q, rid: %s, code: %d, error: %v",
			api, rid, resp.StatusCode, err)
		er.Data = str
		return er
	}

	if err = cbor.Unmarshal(data, output); err != nil {
		str, e := cbor.Diagnose(data)
		if e != nil {
			str = string(data)
		}
		er := gear.ErrInternalServerError.WithMsgf("RequestCBOR failed, url: %q, rid: %s, code: %d, error: %v",
			api, rid, resp.StatusCode, err)
		er.Data = str
		return er
	}
	return nil
}

func CopyHeader(dst http.Header, src http.Header, names ...string) {
	for k, vv := range src {
		if len(names) > 0 && !SliceHas(names, strings.ToLower(k)) {
			continue
		}

		switch len(vv) {
		case 1:
			dst.Set(k, vv[0])
		default:
			dst.Del(k)
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
	}
}

func IsNotFoundErr(err error) bool {
	er := gear.Err.From(err)
	return er != nil && er.Code == http.StatusNotFound
}
