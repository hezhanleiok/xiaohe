package device

import "fmt"

// ForceHandshake 让指定 peer 立刻发起一次握手（本项目的补丁，非上游代码）。
//
// 为什么需要：wireguard-go 自己没有「主动握手」的入口，握手只由三条路径触发 ——
//  1. 有包要发、但没有可用 keypair（SendStagedPackets）；
//  2. 发过数据但 15s 没收到任何已认证包（expiredNewHandshake）；
//  3. 会话快过期（RekeyAfterTime）。
//
// 而「会话内换端点」恰恰不满足第 1 条：UAPI 只改了 peer.endpoint，设备里的旧
// keypair 还在，于是它会拿旧会话往新地址发数据 —— 对端是新机器，不认识这条会话，
// 只会静默丢弃。要等到 15s 定时器才重握手，再加重传，换端点后的恢复因此要 ~20s。
//
// 导出这个方法之后，换端点 + 立刻握手，1s 内就能知道新端点行不行（2026-10-19
// 的日志里，能通的端点握手只要 0.3~1.4s）。
//
// 节流：内部有 RekeyTimeout(5s) 的判定，5s 内重复调用是空操作，不会刷包。
func (device *Device) ForceHandshake(peerPublicKeyHex string) error {
	var publicKey NoisePublicKey
	if err := publicKey.FromHex(peerPublicKeyHex); err != nil {
		return fmt.Errorf("对端公钥无效: %w", err)
	}
	peer := device.LookupPeer(publicKey)
	if peer == nil {
		return fmt.Errorf("对端不存在")
	}
	if !peer.isRunning.Load() {
		return fmt.Errorf("对端未启动")
	}
	peer.SendHandshakeInitiation(false)
	return nil
}
