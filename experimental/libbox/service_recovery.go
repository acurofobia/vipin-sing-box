package libbox

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ServiceRecoveryResponse struct {
	Status      int32
	Body        []byte
	HeadersJSON string
}

type ServiceRecoveryClient struct {
	ctx       context.Context
	cancel    context.CancelFunc
	origin    *url.URL
	transport *http.Transport
	client    *http.Client
}

func (s *CommandServer) NewServiceRecoveryClient(operationID, originHTTPS, outboundTag string) (*ServiceRecoveryClient, error) {
	if s.ctx.Err() != nil {
		return nil, errors.New("cancelled: core stopped")
	}
	ctx, dialer, err := s.ServiceRecoveryTransport(outboundTag)
	if err != nil {
		return nil, errors.New("invalid: recovery transport unavailable")
	}
	client, err := newServiceRecoveryClient(ctx, operationID, originHTTPS, dialer)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(s.ctx, client.Close)
	context.AfterFunc(client.ctx, func() { stop() })
	return client, nil
}

func recoveryURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("invalid: HTTPS origin required")
	}
	return u, nil
}

func recoveryPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	return "443"
}

func newServiceRecoveryClient(parent context.Context, operationID, originHTTPS string, dialer N.Dialer) (*ServiceRecoveryClient, error) {
	if operationID == "" || len(operationID) > 128 || dialer == nil {
		return nil, errors.New("invalid: recovery operation required")
	}
	origin, err := recoveryURL(originHTTPS)
	if err != nil {
		return nil, err
	}
	// The native capability expires even if the Android operation loses its timer.
	ctx, cancel := context.WithTimeout(parent, 300*time.Second)
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
		},
		TLSHandshakeTimeout:    15 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		DisableKeepAlives:      true,
	}
	client := &ServiceRecoveryClient{ctx: ctx, cancel: cancel, origin: origin, transport: transport}
	client.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	context.AfterFunc(ctx, transport.CloseIdleConnections)
	return client, nil
}

func (c *ServiceRecoveryClient) Close() { c.cancel(); c.transport.CloseIdleConnections() }

func (c *ServiceRecoveryClient) Fetch(rawURL, headersJSON string, maxBytes, timeoutMillis int32) (*ServiceRecoveryResponse, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, errors.New("cancelled: recovery ended")
	}
	u, err := recoveryURL(rawURL)
	if err != nil || !strings.EqualFold(u.Hostname(), c.origin.Hostname()) || recoveryPort(u) != recoveryPort(c.origin) {
		return nil, errors.New("invalid: request must use subscription HTTPS origin")
	}
	if maxBytes <= 0 || maxBytes > 8<<20 || timeoutMillis <= 0 || timeoutMillis > 90000 || len(headersJSON) > 16<<10 {
		return nil, errors.New("invalid: request limits")
	}
	var headers map[string]string
	if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
		return nil, errors.New("invalid: request headers")
	}
	ctx, cancel := context.WithTimeout(c.ctx, time.Duration(timeoutMillis)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, errors.New("invalid: request URL")
	}
	for key, value := range headers {
		if strings.ContainsAny(key+value, "\r\n\x00") || strings.EqualFold(key, "Host") || strings.EqualFold(key, "Proxy-Authorization") {
			return nil, errors.New("invalid: request headers")
		}
		req.Header.Set(key, value)
	}
	response, err := c.client.Do(req)
	if err != nil {
		return nil, recoveryRequestError(c.ctx, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, recoveryRequestError(c.ctx, err)
	}
	if len(body) > int(maxBytes) {
		return nil, errors.New("invalid: response exceeds size limit")
	}
	if c.ctx.Err() != nil {
		return nil, errors.New("cancelled: recovery ended")
	}
	encodedHeaders, err := json.Marshal(response.Header)
	if err != nil {
		return nil, errors.New("invalid: response headers")
	}
	return &ServiceRecoveryResponse{Status: int32(response.StatusCode), Body: body, HeadersJSON: string(encodedHeaders)}, nil
}

// Never return net/http's wrapped error: it contains the subscription URL.
func recoveryRequestError(ctx context.Context, err error) error {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return errors.New("cancelled: recovery ended")
	}
	var verification *tls.CertificateVerificationError
	var certificate x509.CertificateInvalidError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var record tls.RecordHeaderError
	if errors.As(err, &verification) || errors.As(err, &certificate) || errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &record) {
		return errors.New("tls: certificate or handshake rejected")
	}
	return errors.New("network: recovery request failed")
}
