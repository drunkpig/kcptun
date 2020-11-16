package main

import (
	"encoding/json"
	"os"
	"sync"
	"github.com/juju/ratelimit"
)

// TrafficAudit for ratelimit, traffic statistics
type TrafficAudit struct{
	MuxWaitGroup             sync.WaitGroup     //一个客户端会有多个mux连接，要等全部连接都释放才从内存里去掉
	RateLimitBucket          *ratelimit.Bucket   // 使用这个bucket对属于同一个用户(email)进行限速，流量统计

	//TrafficUpdatorLock       sync.Mutex        //采用chan没有必要用锁了
	UpstreamTrafficByte      float64             // 上行流量统计
	DownstreamTrafficByte    float64             // 下行流量
}

func newTrafficAudit() *TrafficAudit  {
	ta := new(TrafficAudit)
	ta.RateLimitBucket = ratelimit.NewBucketWithRate(100*1024, 1*1024*1024) //先测试100KB/s
	ta.UpstreamTrafficByte = 0
	ta.DownstreamTrafficByte = 0
	return ta
}

func (ta *TrafficAudit) updateTraffic(upByte float64, downByte float64){
	//采用chan机制，没有必要再用锁了
	//ta.TrafficUpdatorLock.Lock()
	//defer ta.TrafficUpdatorLock.Unlock()
	ta.UpstreamTrafficByte += upByte
	ta.DownstreamTrafficByte += downByte
}

type AuditorMgr struct {
	mu sync.Mutex
	auditor  map[string]*TrafficAudit  // ip:TrafficAudit
}

func NewTrafficAuditor() *AuditorMgr {
	auditor := new(AuditorMgr)
	auditor.auditor = make(map[string]*TrafficAudit, 10)
	return auditor
}

//返回值代表是否是新添加的
func(this *AuditorMgr) AddAuditor(email string)bool{
	//如果email的auditor已经存在就增加引用，否则新建
	this.mu.Lock()
	defer this.mu.Unlock()
	if _, ok := this.auditor[email]; ok{
		// email相关的结构已经存在
		return false
	}else{
		ta := newTrafficAudit()
		this.auditor[email] = ta
		return true
	}
}

func(this *AuditorMgr)UpdateTraffic(email string, upBytes, downBytes float64){
	if auditor, ok := this.auditor[email]; ok{
		auditor.updateTraffic(upBytes, downBytes)
	}else{
		// TODO log error
	}
}

// Config for server
type Config struct {
	Redis        string `json:"redis"`
	TokenLength  int `json:"tokenlength"`  // 鉴权token的长度，36
	Bandwidth    int `json:"bandwidth"`
	TrafficAuditor *AuditorMgr

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
