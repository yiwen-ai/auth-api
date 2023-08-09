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
	userAgent = fmt.Sprintf("Go/%v auth-api", runtime.Version())
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

var ErrNotFound = gear.ErrNotFound

type ContextHTTPHeader http.Header

func RequestJSON(ctx context.Context, cli *http.Client, method, api string, input, output any) error {
	if ctx.Err() != nil {
		return nil
	}

	var err error
	var body io.Reader
	if input != nil {
		data, ok := input.([]byte)
		if !ok {
			if data, err = json.Marshal(input); err != nil {
				return err
			}
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, api, body)
	if err != nil {
		return err
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

		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return ErrNotFound
	}

	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 206 || err != nil {
		return fmt.Errorf("RequestJSON %q failed, rid: %s, code: %d, error: %v, body: %s",
			api, rid, resp.StatusCode, err, string(data))
	}
	// fmt.Println(string(data))
	return json.Unmarshal(data, output)
}

func RequestCBOR(ctx context.Context, cli *http.Client, method, api string, input, output any) error {
	if ctx.Err() != nil {
		return nil
	}

	var err error
	var body io.Reader
	if input != nil {
		data, ok := input.([]byte)
		if !ok {
			if data, err = cbor.Marshal(input); err != nil {
				return err
			}
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, api, body)
	if err != nil {
		return err
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

		return err
	}

	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return ErrNotFound
	}

	data, err := io.ReadAll(resp.Body)
	if resp.StatusCode > 206 || err != nil {
		str, e := cbor.Diagnose(data)
		if e != nil {
			str = string(data)
		}
		return fmt.Errorf("RequestCBOR %q failed, rid: %s, code: %d, error: %v, body: %s",
			api, rid, resp.StatusCode, err, str)
	}

	return cbor.Unmarshal(data, output)
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
