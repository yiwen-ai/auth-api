package service

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/teambition/gear"

	"github.com/yiwen-ai/auth-api/src/conf"
	"github.com/yiwen-ai/auth-api/src/util"
)

func init() {
	util.DigProvide(NewOSS)
}

type OSS struct {
	UrlBase string
	Prefix  string
	bucket  *oss.Bucket
}

func NewOSS() *OSS {
	cfg := conf.Config.OSS
	client, err := oss.New(cfg.Endpoint, cfg.AccessKeyId, cfg.AccessKeySecret)
	if err != nil {
		panic(err)
	}
	bucket, err := client.Bucket(cfg.Bucket)
	if err != nil {
		panic(err)
	}

	return &OSS{
		UrlBase: cfg.UrlBase,
		Prefix:  cfg.Prefix,
		bucket:  bucket,
	}
}

func (s *OSS) SavePicture(ctx context.Context, imgPath, imgUrl string) (string, error) {
	ctype, reader, err := GetPicture(ctx, imgUrl)
	if err != nil {
		return "", err
	}

	objectKey := s.Prefix + imgPath
	if err := s.bucket.PutObject(objectKey, reader, oss.ContentType(ctype),
		oss.CacheControl("public"), oss.ContentDisposition("inline")); err != nil {
		return "", err
	}

	return s.UrlBase + objectKey, nil
}

func GetPicture(ctx context.Context, imgUrl string) (string, io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", imgUrl, nil)
	if err != nil {
		return "", nil, err
	}

	resp, err := fileHTTPClient.Do(req)
	if err != nil {
		if err.(*url.Error).Unwrap() == context.Canceled {
			return "", nil, gear.ErrClientClosedRequest
		}

		return "", nil, err
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return "", nil, gear.Err.WithCode(resp.StatusCode).WithMsg(string(data))
	}

	ct := strings.ToLower(resp.Header.Get(gear.HeaderContentType))
	if !strings.Contains(ct, "image") {
		resp.Body.Close()
		return "", nil, gear.ErrUnsupportedMediaType.WithMsg(ct)
	}

	return ct, resp.Body, nil
}

var tr = &http.Transport{
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

var fileHTTPClient = &http.Client{
	Transport: tr,
	Timeout:   time.Second * 60,
}
