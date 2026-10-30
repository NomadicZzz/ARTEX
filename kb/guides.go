package kb

// The public feeds carry no real detection content, only an impact summary. Each
// source stamps a boilerplate guide so the row is never blank. Those strings are
// how a synced row is recognised as hollow: no PoC, not KEV, and a guide that
// says nothing beyond "look it up yourself". Kept here so sources and the purge
// share one definition.
const (
	GuideKEV  = "该条目位于 CISA KEV，表示已有在野利用。检测时对照受影响产品与版本做授权验证，命中本身不是漏洞证据。"
	GuideNVD  = "NVD 描述只说明公开影响面。检测需在授权资产上按受影响版本实际触发，版本匹配本身不能记为漏洞。"
	GuideGHSA = "GHSA 只提供公开公告。按受影响包与版本做授权检测，公告命中不能代替实际触发。"
	GuideAVD  = "阿里云 AVD 页面只提供公开线索。需要在授权资产上按受影响版本实际触发后才能记为漏洞。"
	GuideFeed = "RSS/公告只提供背景。检测思路需结合受影响产品在授权范围内验证，文章本身不是漏洞证据。"
)

// GuideKEVRansomware is appended to GuideKEV when the catalog marks ransomware use.
const GuideKEVRansomware = " KEV 标注已知勒索利用。"

// DefaultHollowGuides lists guides that carry no detection signal. A synced
// entry whose guide is one of these is a hollow shell.
func DefaultHollowGuides() []string {
	return []string{GuideKEV, GuideNVD, GuideGHSA, GuideAVD, GuideFeed}
}
