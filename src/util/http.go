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
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/klauspost/compress/gzhttp"
	"github.com/teambition/gear"
)

func init() {
	userAgent = fmt.Sprintf("Go/%v auth-api", runtime.Version())
}

type ContextHTTPHeader http.Header

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
	TLSHandshakeTimeout:   3 * time.Second,
	ExpectContinueTimeout: 4 * time.Second,
	ResponseHeaderTimeout: 5 * time.Second,
}

var HTTPClient = &http.Client{
	Transport: gzhttp.Transport(internalTr),
	Timeout:   time.Second * 5,
}

func RequestJSON(ctx context.Context, cli *http.Client, method, api string, input, output any) error {
	if ctx.Err() != nil {
		return nil
	}

	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
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

	resp, err := cli.Do(req)
	if err != nil {
		if err.(*url.Error).Unwrap() == context.Canceled {
			return gear.ErrClientClosedRequest
		}

		return err
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || err != nil {
		return fmt.Errorf("RequestJSON %q failed, code: %d, error: %v, body: %s",
			api, resp.StatusCode, err, string(data))
	}

	return json.Unmarshal(data, output)
}

func RequestCBOR(ctx context.Context, cli *http.Client, method, api string, input, output any) error {
	if ctx.Err() != nil {
		return nil
	}

	var body io.Reader
	if input != nil {
		data, err := cbor.Marshal(input)
		if err != nil {
			return err
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

	resp, err := cli.Do(req)
	if err != nil {
		if err.(*url.Error).Unwrap() == context.Canceled {
			return gear.ErrClientClosedRequest
		}

		return err
	}

	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || err != nil {
		return fmt.Errorf("RequestCBOR %q failed, code: %d, error: %v, body: %s",
			api, resp.StatusCode, err, string(data))
	}

	return cbor.Unmarshal(data, output)
}

func CopyHeader(dst http.Header, src http.Header) {
	for k, vv := range src {
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
