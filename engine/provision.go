package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/curve25519"
)

// WARP 注册。
//
// 原生核心需要一份 WireGuard 身份（私钥 + 对端公钥 + 接口地址）。电脑版是
// 由 Aether 核心把 aether.toml 准备好的；安卓这边没有那个文件，所以自己注册
// 一份：向 Cloudflare 的注册接口提交一个 X25519 公钥，拿回同一条账号配置。
//
// 注意（来自电脑版的实测结论，别再踩）：WARP 接受「reserved 三个字节为 0」
// 的标准握手，不需要 client_id 参与握手，所以这里**只**保存私钥/对端公钥/
// 地址，不保存也不注入 reserved。
const warpRegisterURL = "https://api.cloudflareclient.com/v0a2158/reg"

// 默认端点。真正的优选在后续版本里做（扫描 2408/500/1701/4500），这里先钉
// 一个官方入口，保证「能连上」这条主线先闭环。
const defaultWARPEndpoint = "engage.cloudflareclient.com:2408"

type warpIdentity struct {
	PrivateKey    string   `json:"privateKey"`
	PeerPublicKey string   `json:"peerPublicKey"`
	IPv4          string   `json:"ipv4"`
	IPv6          string   `json:"ipv6"`
	Endpoint      string   `json:"endpoint"`
	DNS           []string `json:"dns"`
}

// 注册响应里的 config 段（两种响应形状共用同一份结构）。
type warpConfig struct {
	Peers []struct {
		PublicKey string `json:"public_key"`
		Endpoint  struct {
			Host string `json:"host"`
		} `json:"endpoint"`
	} `json:"peers"`
	Interface struct {
		Addresses struct {
			V4 string `json:"v4"`
			V6 string `json:"v6"`
		} `json:"addresses"`
		DNS []string `json:"dns"`
	} `json:"interface"`
}

// ProvisionWARP 注册一份新的 WARP 身份，返回 JSON 字符串（字段见 warpIdentity）。
func (e *Engine) ProvisionWARP() (string, error) {
	return e.provision(&http.Client{Timeout: 25 * time.Second})
}

// ProvisionWARPOverSocks 和 ProvisionWARP 一样，只是注册请求走一个 SOCKS5 代理。
//
// 给「api.cloudflareclient.com 被墙、直接注册 TLS 超时」的环境兜底：用赛风当出口，
// 注册的 DNS 解析和 TLS 握手都发生在代理另一端，运营商看不到 SNI，自然绕开阻断。
func (e *Engine) ProvisionWARPOverSocks(socksAddr string) (string, error) {
	if socksAddr == "" {
		return "", fmt.Errorf("缺少 SOCKS5 代理地址")
	}
	tr := &http.Transport{
		DialContext:         socks5Dial(socksAddr),
		TLSHandshakeTimeout: 25 * time.Second,
	}
	return e.provision(&http.Client{Timeout: 60 * time.Second, Transport: tr})
}

// provision 是注册主体：生成 X25519 密钥 → POST 到 Cloudflare → 解析身份。
// client 由调用方决定（直连或走 socks），两个入口共用同一套逻辑。
func (e *Engine) provision(client *http.Client) (string, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", fmt.Errorf("生成私钥失败: %w", err)
	}
	// X25519 要求的位裁剪，与 wg 工具一致。
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", fmt.Errorf("推导公钥失败: %w", err)
	}

	body, _ := json.Marshal(map[string]any{
		"key":           base64.StdEncoding.EncodeToString(pub),
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":         "PC",
		"serial_number": "",
		"locale":        "en_US",
		"type":          "Android",
	})

	req, err := http.NewRequest(http.MethodPost, warpRegisterURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("注册请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("注册被拒绝：HTTP %d %s", resp.StatusCode, trimBody(raw))
	}

	// 注册接口的响应形状跟 CF-Client-Version 走，两种都见过：
	//   - 老版（a-6.x）：config 直接在顶层，和 id/account/token 平级；
	//   - 新版包装：{"result": {"config": {...}}}。
	// 只解析其中一种就会出现「响应里明明有 public_key，却报没有对端公钥」。
	var parsed struct {
		Config warpConfig `json:"config"`
		Result struct {
			Config warpConfig `json:"config"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("注册响应解析失败: %w（%s）", err, trimBody(raw))
	}
	cfg := parsed.Config
	if len(cfg.Peers) == 0 && len(parsed.Result.Config.Peers) > 0 {
		cfg = parsed.Result.Config
	}
	if len(cfg.Peers) == 0 || cfg.Peers[0].PublicKey == "" {
		return "", fmt.Errorf("注册响应里没有对端公钥：%s", trimBody(raw))
	}
	dns := cfg.Interface.DNS
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "1.0.0.1"}
	}

	id := warpIdentity{
		PrivateKey:    base64.StdEncoding.EncodeToString(priv),
		PeerPublicKey: cfg.Peers[0].PublicKey,
		IPv4:          cfg.Interface.Addresses.V4,
		IPv6:          cfg.Interface.Addresses.V6,
		Endpoint:      defaultWARPEndpoint,
		DNS:           dns,
	}
	out, err := json.Marshal(id)
	if err != nil {
		return "", err
	}
	e.logs.add("INFO", fmt.Sprintf("WARP 身份已注册：v4=%s v6=%s endpoint=%s",
		id.IPv4, id.IPv6, id.Endpoint))
	return string(out), nil
}

// socks5Dial 返回一个能连到 [socksAddr] 的 SOCKS5 的拨号函数，给 http.Transport
// 用。target 里的域名以 ATYP=3 原样交给代理去解析，这样 DNS 和 TLS 都发生在
// 代理出口侧，本地网络只看得到一条到赛风 socks 的本地连接。
func socks5Dial(socksAddr string) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, target string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("端口 %q 无效", portStr)
		}
		return socks5Connect(socksAddr, host, uint16(port), 25*time.Second)
	}
}

func trimBody(b []byte) string {
	s := string(b)
	// 200 字节只够看到 id/type/key，连 account 都切一半——上一轮就是因此看不出
	// 「config 其实在顶层」。留 400，够看到 peers。
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
