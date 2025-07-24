package routeros

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
)

type rest struct {
	username string
	password string
	url      string
	client   *http.Client
}

func (r *rest) makeRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, fmt.Sprintf("%s/rest%s", r.url, url), body)
	if err != nil {
		return nil, err
	}
	encCreds := base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%s:%s", r.username, r.password))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encCreds))
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusBadRequest {
		detail := &struct {
			Detail string `json:"detail"`
		}{}
		if err := json.NewDecoder(resp.Body).Decode(detail); err != nil {
			return nil, err
		}
		if len(detail.Detail) > 0 {
			return nil, fmt.Errorf("api request error: %s", detail.Detail)
		}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected http status: %s", resp.Status)
	}
	if method == http.MethodGet && resp.Header.Get("Content-Type") != "application/json" {
		return nil, fmt.Errorf("unexpected content-type: %s", resp.Header.Get("Content-Type"))
	}
	return resp, nil
}

func (r *rest) getMatchFQDNs(ctx context.Context) ([]string, error) {
	resp, err := r.makeRequest(ctx, http.MethodGet, "/ip/firewall/filter?disabled=false&.proplist=dst-address-list", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	uresp := []struct {
		ID             string `json:".id"`
		DstAddressList string `json:"dst-address-list"`
	}{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&uresp); err != nil {
		return nil, err
	}
	fqdns := make([]string, 0)
	for _, v := range uresp {
		if slices.Contains(fqdns, v.DstAddressList) {
			continue
		}
		fqdns = append(fqdns, v.DstAddressList)
	}
	return fqdns, nil
}

func (r *rest) getAddressListRecord(ctx context.Context, address, list string) (string, uint, error) {
	resp, err := r.makeRequest(ctx, http.MethodGet, fmt.Sprintf("/ip/firewall/address-list?address=%s&list=%s&.proplist=id,timeout", address, list), nil)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	uresp := []struct {
		ID      string `json:".id"`
		Timeout string `json:"timeout"`
	}{}
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&uresp); err != nil {
		return "", 0, err
	}
	if len(uresp) == 0 {
		return "", 0, nil
	}
	d, err := time.ParseDuration(uresp[0].Timeout)
	if err != nil {
		return "", 0, err
	}
	return uresp[0].ID, uint(d.Seconds()), nil
}

func (r *rest) addAddressListRecord(ctx context.Context, name, ip string, ttl uint) error {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(struct {
		List    string `json:"list"`
		Address string `json:"address"`
		Timeout uint   `json:"timeout"`
		Dynamic bool   `json:"dynamic"`
	}{
		List:    name,
		Address: ip,
		Timeout: ttl,
		Dynamic: true,
	})
	if err != nil {
		return err
	}
	resp, err := r.makeRequest(ctx, http.MethodPut, "/ip/firewall/address-list", buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (r *rest) setAddressListRecord(ctx context.Context, id string, ttl uint) error {
	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(struct {
		Timeout uint `json:"timeout"`
	}{
		Timeout: ttl,
	})
	if err != nil {
		return err
	}
	resp, err := r.makeRequest(ctx, http.MethodPatch, fmt.Sprintf("/ip/firewall/address-list/%s", id), buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
