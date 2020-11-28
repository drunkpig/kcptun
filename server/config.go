package main

import (
	"encoding/json"
	"github.com/juju/ratelimit"
	"log"
	"os"
	"sync"
)

// TrafficAudit for ratelimit, traffic statistics
type TrafficAudit struct {
	Email           string
	ConnectCnt      int               //引用的次数, 因为一个token可以创建多个连接
	RateLimitBucket *ratelimit.Bucket // 使用这个bucket对属于同一个用户(email)进行限速，流量统计

	UpstreamTrafficByte   int64 // 上行流量统计
	DownstreamTrafficByte int64 // 下行流量
}

func newTrafficAudit(email string) *TrafficAudit {
	ta := new(TrafficAudit)
	ta.Email = email
	ta.RateLimitBucket = ratelimit.NewBucketWithRate(100*1024, 1*1024*1024) //先测试100KB/s
	ta.UpstreamTrafficByte = 0
	ta.DownstreamTrafficByte = 0
	return ta
}

func (ta *TrafficAudit) updateTraffic(upByte, downByte int64) {
	//采用chan机制，没有必要再用锁了
	//ta.TrafficUpdatorLock.Lock()
	//defer ta.TrafficUpdatorLock.Unlock()
	ta.UpstreamTrafficByte += upByte
	ta.DownstreamTrafficByte += downByte
}

type AuditorMgr struct {
	mu        sync.Mutex
	auditor   map[string]*TrafficAudit // token:TrafficAudit
	trafficCh chan string              // 统计流量
}

func NewTrafficAuditorMgr() *AuditorMgr {
	auditor := new(AuditorMgr)
	auditor.auditor = make(map[string]*TrafficAudit, 200)
	auditor.trafficCh = make(chan string)
	return auditor
}

//返回值代表是否是新添加的
func (this *AuditorMgr) AddAuditor(token string, email string) bool {
	//如果email的auditor已经存在就增加引用，否则新建
	this.mu.Lock()
	defer this.mu.Unlock()
	if au, ok := this.auditor[token]; ok {
		// email相关的结构已经存在
		au.ConnectCnt++
		return false
	} else {
		ta := newTrafficAudit(email)
		ta.ConnectCnt++
		this.auditor[token] = ta
		return true
	}
}

func (this *AuditorMgr) DelAuditorRef(token string) {
	this.mu.Lock()
	defer this.mu.Unlock()
	if au, ok := this.auditor[token]; ok {
		// email相关的结构已经存在
		au.ConnectCnt--
	} else {
		log.Printf("ERROR %s not exists", token)
	}
}

func (this *AuditorMgr) removeAuditor(token string) bool {
	this.mu.Lock()
	defer this.mu.Unlock()
	if au, ok := this.auditor[token]; ok {
		// email相关的结构已经存在
		if au.ConnectCnt <= 0 {
			delete(this.auditor, token)
			return true
		}
		return false
	} else {
		log.Printf("ERROR %s not exists", token)
		return false
	}
}

func (this *AuditorMgr) UpdateTraffic(token string, upBytes, downBytes int64) {
	if auditor, ok := this.auditor[token]; ok {
		auditor.updateTraffic(upBytes, downBytes)
	} else {
		log.Printf("ERROR %s not exists, can not update traffic", token)
	}
}

// Config for server
type Config struct {
	Redis                 string `json:"redis"`
	TokenLength           int    `json:"tokenlength"` // 鉴权token的长度，36
	Bandwidth             int    `json:"bandwidth"`
	AuditorMgr            *AuditorMgr
	TrafficUpdateUrl      string `json:"trafficupdateurl"`
	DeviceStatusUpdateUrl string `json:"devicestatusupdateurl"`

	Listen       string `json:"listen"`
	Target       string `json:"target"`
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	SmuxBuf      int    `json:"smuxbuf"`
	StreamBuf    int    `json:"streambuf"`
	SmuxVer      int    `json:"smuxver"`
	KeepAlive    int    `json:"keepalive"`
	Log          string `json:"log"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
	Pprof        bool   `json:"pprof"`
	Quiet        bool   `json:"quiet"`
	TCP          bool   `json:"tcp"`
}

func parseJSONConfig(config *Config, path string) error {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}
