package engine

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Config 是引擎需要的全部 WireGuard 参数。字段名即 JSON 名（Kotlin 侧拼）。
type Config struct {
	PrivateKey    string `json:"privateKey"`    // base64, 32 字节
	PeerPublicKey string `json:"peerPublicKey"` // base64, 32 字节
	Endpoint      string `json:"endpoint"`      // ip:port
	MTU           int    `json:"mtu"`
	Keepalive     int    `json:"keepalive"` // 0 = 关闭

	// Address 是这份身份在隧道里的接口地址（WARP 注册给的 172.16.0.2）。
	// 只有要挂用户态协议栈（GOOL 外层 / 赛风上游）时才用得到：
	// 没有它协议栈就没有源地址，任何拨号都会失败。普通 WG 不需要。
	Address string `json:"address"`

	// DNS 是「隧道内」解析用的服务器（用户态协议栈里发 53 查询）。
	// 空 = 1.1.1.1。只有挂用户态协议栈的路径会用到。
	DNS string `json:"dns"`

	// AmneziaWG 混淆（与电脑版同一套 UAPI 键：jc/jmin/jmax/i1）。
	// JunkCount == 0 时就是标准 WireGuard —— 对 WARP 也成立。
	JunkCount   int    `json:"junkCount"`
	JunkMinSize int    `json:"junkMinSize"`
	JunkMaxSize int    `json:"junkMaxSize"`
	JunkI1      string `json:"junkI1"` // hex 字符串，空 = 不发假首包

	// InnerCandidates 只用于 GOOL 的**内层**：可以依次尝试的落点（ip:port）。
	//
	// 为什么需要：GOOL 的内层包要穿过外层隧道、落到 Cloudflare 自己的另一个边缘。
	// 这条线路上「探针通、握手不回」的边缘整段存在（2026-10-18 22:48 的日志：
	// 内层挑了 162.159.193.238:968，外层握手 + 数据面全过，内层 8s 零回包）。
	// 落点挑错时换一个再试，比把整条 GOOL 拆掉重来便宜得多——外层是好的。
	// 空 = 只用 Endpoint。
	InnerCandidates []string `json:"innerCandidates"`
}

// buildUAPI 渲染 wireguard-go 的 UAPI 文本。
//
// 键必须 hex 编码（上游如此），所以 base64 的密钥要转一遍。顺序与电脑版
// internal/wgtun 的 buildUAPI 保持一致：先私钥、再 peer，最后才是设备级
// 的混淆键（jc/jmin/jmax/i1 在整段读完后才生效）。
func buildUAPI(cfg Config) (string, error) {
	priv, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("私钥无效: %w", err)
	}
	pub, err := keyToHex(cfg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("对端公钥无效: %w", err)
	}
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return "", fmt.Errorf("缺少 endpoint（ip:port）")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	b.WriteString("listen_port=0\n")
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.Endpoint)
	b.WriteString("allowed_ip=0.0.0.0/0\n")
	b.WriteString("allowed_ip=::/0\n")
	if cfg.Keepalive > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", cfg.Keepalive)
	}
	if cfg.JunkI1 != "" {
		if _, err := hex.DecodeString(cfg.JunkI1); err != nil {
			return "", fmt.Errorf("i1 不是合法 hex: %w", err)
		}
		fmt.Fprintf(&b, "i1=%s\n", cfg.JunkI1)
	}
	if cfg.JunkCount > 0 {
		jmin := cfg.JunkMinSize
		jmax := cfg.JunkMaxSize
		if jmin <= 0 {
			jmin = 10
		}
		if jmax < jmin {
			jmax = jmin + 40
		}
		fmt.Fprintf(&b, "jc=%d\n", cfg.JunkCount)
		fmt.Fprintf(&b, "jmin=%d\n", jmin)
		fmt.Fprintf(&b, "jmax=%d\n", jmax)
	}
	return b.String(), nil
}

func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("密钥长度 %d，应为 32", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
