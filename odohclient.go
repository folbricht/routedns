package rdns

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	odoh "github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

const (
	ODOH_CONFIG_PATH  = "/.well-known/odohconfigs"
	DOH_CONTENT_TYPE  = "application/dns-message"
	ODOH_CONTENT_TYPE = "application/oblivious-dns-message"
)

// ODoHClient is a Oblivious DNS client.
type ODoHClient struct {
	id         string
	targetName string
	targetPath string
	targetPort string
	proxy      *DoHClient

	odohConfig       *odoh.ObliviousDoHConfig
	odohConfigString string
	odohConfigExpiry time.Time
	mu               sync.Mutex
}

var _ Resolver = &DoHClient{}

func NewODoHClient(id, proxy, target, targetConfig string, opt DoHClientOptions) (*ODoHClient, error) {
	if proxy == "" {
		Log.Warn("Attention! no ODoH proxy defined, using the target as proxy")
		proxy = target
	}

	dohProxy, err := NewDoHClient(id, proxy, opt)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	return &ODoHClient{
		id:               id,
		proxy:            dohProxy,
		targetName:       u.Hostname(),
		targetPort:       u.Port(),
		targetPath:       u.Path,
		odohConfigString: targetConfig,
	}, nil
}

// Resolve a DNS query.
func (d *ODoHClient) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	// Build the encrypted query. The target key is retrieved on-demand
	msg, queryContext, err := d.buildTargetQuery(q)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), d.proxy.opt.QueryTimeout)
	defer cancel()

	// Build a regular DoH request. It needs to be modified for a proxy.
	req, err := d.proxy.buildRequest(ctx, msg.Marshal())
	if err != nil {
		return nil, err
	}

	// Modify it for odoh (headers and query params)
	d.customizeRequest(req)

	// Perform the HTTP call to the proxy (which forwards to the target)
	resp, err := d.proxy.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Decode and decrypt the response
	return d.decodeProxyResponse(resp, queryContext)
}

func (d *ODoHClient) String() string {
	return d.id
}

// Check the HTTP response status code, parse out the response DNS message and decrypt it.
func (d *ODoHClient) decodeProxyResponse(resp *http.Response, queryContext odoh.QueryContext) (*dns.Msg, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		d.proxy.metrics.err.Add(fmt.Sprintf("http%d", resp.StatusCode), 1)
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	if resp.Header.Get("content-type") != "application/oblivious-dns-message" {
		return nil, errors.New("received invalid odoh header from proxy")
	}
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		d.proxy.metrics.err.Add("read", 1)
		return nil, err
	}
	odohQueryResponse, err := odoh.UnmarshalDNSMessage(rb)
	if err != nil {
		d.proxy.metrics.err.Add("decode", 1)
		return nil, err
	}
	decryptedResponse, err := queryContext.OpenAnswer(odohQueryResponse)
	if err != nil {
		d.proxy.metrics.err.Add("decrypt", 1)
		return nil, err
	}
	a := new(dns.Msg)
	err = a.Unpack(decryptedResponse)
	if err != nil {
		d.proxy.metrics.err.Add("unpack", 1)
	} else {
		d.proxy.metrics.response.Add(rCode(a), 1)
	}
	return a, err
}

// Modify a DoH request for proxy-use. The URL and headers need to be updated.
func (d *ODoHClient) customizeRequest(req *http.Request) {
	req.Header.Set("content-type", ODOH_CONTENT_TYPE)
	req.Header.Add("accept", ODOH_CONTENT_TYPE)
	query := req.URL.Query()
	query.Add("targethost", d.targetName)
	query.Add("targetpath", d.targetPath)
	req.URL.RawQuery = query.Encode()
}

// Marshal and encrypt the original query with the key for the target.
func (d *ODoHClient) buildTargetQuery(q *dns.Msg) (odoh.ObliviousDNSMessage, odoh.QueryContext, error) {
	config, err := d.getTargetConfig()
	if err != nil {
		return odoh.ObliviousDNSMessage{}, odoh.QueryContext{}, err
	}
	key := config.Contents
	msg, err := q.Pack()
	if err != nil {
		return odoh.ObliviousDNSMessage{}, odoh.QueryContext{}, err
	}
	odohQ := odoh.CreateObliviousDNSQuery(msg, 0)
	return key.EncryptQuery(odohQ)
}

// Get the current (cached) target config or refresh it if expired.
func (d *ODoHClient) getTargetConfig() (*odoh.ObliviousDoHConfig, error) {
	var err error
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.odohConfigString) != 0 {
		Log.Debug("loading preset ODoH config")
		configBytes, err := hex.DecodeString(d.odohConfigString)
		if err != nil {
			return nil, fmt.Errorf("failed to decode odohConfig: %w", err)
		}
		odohConfigs, err := odoh.UnmarshalObliviousDoHConfigs(configBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal odohConfig: %w", err)
		}
		d.odohConfig = &odohConfigs.Configs[0]
	} else if d.odohConfig == nil || time.Now().After(d.odohConfigExpiry) {
		d.odohConfig, d.odohConfigExpiry, err = d.refreshTargetKey()
	}
	return d.odohConfig, err
}

func (d *ODoHClient) refreshTargetKey() (*odoh.ObliviousDoHConfig, time.Time, error) {
	var url string = "https://" + d.targetName + ":" + d.targetPort + ODOH_CONFIG_PATH
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, time.Time{}, err
	}

	resp, err := d.proxy.do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Time{}, err
	}
	odohConfigs, err := odoh.UnmarshalObliviousDoHConfigs(bodyBytes)
	expiry := time.Now().Add(24 * time.Hour)

	Log.Printf("got config: %x", odohConfigs.Marshal())
	return &odohConfigs.Configs[0], expiry, err
}
