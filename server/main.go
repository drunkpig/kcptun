package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/mozillazg/request"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/urfave/cli"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/kcptun/generic"
	"github.com/xtaci/smux"
	"github.com/xtaci/tcpraw"
	"github.com/tidwall/gjson"
)

const (
	// SALT is use for pbkdf2 key expansion
	SALT = "kcp-go"
	// maximum supported smux version
	maxSmuxVer = 2
	// stream copy buffer size
	bufSize = 4096
)

type RedisServer struct {
	Server *redis.Client
}

var REDIS_SERVER *RedisServer = nil
var redisInitLock sync.Once

func NewRedisServer(redis_url string) *RedisServer{
	redisInitLock.Do(func() {
		options, _ := redis.ParseURL(redis_url)
		s := redis.NewClient(options)
		REDIS_SERVER = &RedisServer{Server: s}
	})
	return REDIS_SERVER
}


// VERSION is injected by buildflags
var VERSION = "SELFBUILD"

// handle multiplex-ed connection
func handleMux(conn net.Conn, config *Config) {
	// check if target is unix domain socket
	var isUnix bool
	var userEmail string
	var isMuxAuthed bool = false
	if _, _, err := net.SplitHostPort(config.Target); err != nil {
		isUnix = true
	}
	log.Println("smux version:", config.SmuxVer, "on connection:", conn.LocalAddr(), "->", conn.RemoteAddr())

	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.SmuxVer
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.MaxStreamBuffer = config.StreamBuf
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		log.Println(err)
		return
	}
	defer mux.Close()

	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Println(err)
			return
		}

		//==========================================auth check
		if !isMuxAuthed{
			authToken := make([]byte, config.TokenLength)
			n, err := stream.Read(authToken)//带超时的read,
			if err!=nil || n!=config.TokenLength{
				log.Println("token length error: length=", n)
				stream.Write([]byte("ERR"))
				isMuxAuthed = false
				return
			}
			authTokenAsRedisKey := string(authToken[:])
			//get from redis
			redisServ := NewRedisServer(config.Redis)
			defer redisServ.Server.Close()
			jsonval, err := redisServ.Server.Get(context.Background(), authTokenAsRedisKey).Result()
			if err!=nil{
				log.Println("redis error: ", err)
				isMuxAuthed = false
				stream.Write([]byte("ERR"))
				return
			}else{
				if err!=redis.Nil{
					log.Println("authentication succ! token=", authTokenAsRedisKey)
					email := gjson.Get(jsonval, "email")
					userEmail = email.String()
					log.Println(userEmail)
					totalTrafficGb, err1 := redisServ.Server.Get(context.Background(), userEmail+"_total_gb").Int64()
					usedTrafficKb, err2 := redisServ.Server.Get(context.Background(), userEmail+"_used_kb").Int64()
					if err1==nil && err2==nil{
						if totalTrafficGb*1024*1024<=usedTrafficKb{ //超过了流量限制
							isMuxAuthed = false
							stream.Write([]byte("ERR"))
						}
					}
					config.AuditorMgr.AddAuditor(userEmail)
					isMuxAuthed = true
					stream.Write([]byte("OKK"))
				}else{
					log.Println("token not exists! token=", authTokenAsRedisKey)
					isMuxAuthed = false
					return
				}
			}
		}
		//==================================================
		go func(p1 *smux.Stream) {
			var p2 net.Conn
			var err error
			if !isUnix {
				p2, err = net.Dial("tcp", config.Target)
			} else {
				p2, err = net.Dial("unix", config.Target)
			}

			if err != nil {
				log.Println(err)
				p1.Close()
				return
			}
			handleClient(p1, p2, config, &userEmail)
		}(stream)
	}
}

func handleClient(p1 *smux.Stream, p2 net.Conn, config *Config, email *string) {
	quiet := config.Quiet
	logln := func(v ...interface{}) {
		if !quiet {
			log.Println(v...)
		}
	}

	defer p1.Close()
	defer p2.Close()

	logln("stream opened", "in:", fmt.Sprint(p1.RemoteAddr(), "(", p1.ID(), ")"), "out:", p2.RemoteAddr())
	defer logln("stream closed", "in:", fmt.Sprint(p1.RemoteAddr(), "(", p1.ID(), ")"), "out:", p2.RemoteAddr())

	// start tunnel & wait for tunnel termination
	streamCopy := func(dst io.Writer, src io.ReadCloser, config *Config, isUpStream bool) {
		if nBytes, err := generic.Copy(dst, src); err != nil {
			if err == smux.ErrInvalidProtocol {
				log.Println("smux", err, "in:", fmt.Sprint(p1.RemoteAddr(), "(", p1.ID(), ")"), "out:", p2.RemoteAddr())
			}else if nBytes>0{
				//记录流量
				if isUpStream {
					config.AuditorMgr.trafficCh<- *email + "," + strconv.FormatInt(nBytes, 10) + ",0"//TODO
				}else{
					config.AuditorMgr.trafficCh<- *email + "," + "0,"+ strconv.FormatInt(nBytes, 10) //TODO
				}
			}
		}
		p1.Close()
		p2.Close()
	}

	go streamCopy(p2, p1, config, true)//上行up C-S
	streamCopy(p1, p2, config, false)   //下行 S-C
}

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func main() {
	rand.Seed(int64(time.Now().Nanosecond()))
	if VERSION == "SELFBUILD" {
		// add more log flags for debugging
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	myApp := cli.NewApp()
	myApp.Name = "kcptun"
	myApp.Usage = "server(with SMUX)"
	myApp.Version = VERSION
	myApp.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "redis,r",
			Value: "redis://:@localhost:6379",//redis://arbitrary_usrname:password@ipaddress:6379/0
			Usage: "redis server address",
		},
		cli.IntFlag{
			Name:  "tokenlength",
			Value: 36,
			Usage: "authentication token length",
		},
		cli.IntFlag{
			Name:  "bandwidth",
			Value: 100,
			Usage: "VPS server max bandwidth (Mbps)",
		},
		cli.StringFlag{
			Name:  "trafficupdateurl",
			Value: "",
			Usage: "Traffic auditor url",
		},
		cli.StringFlag{
			Name:  "listen,l",
			Value: ":29900",
			Usage: "kcp server listen address",
		},
		cli.StringFlag{
			Name:  "target, t",
			Value: "127.0.0.1:12948",
			Usage: "target server address, or path/to/unix_socket",
		},
		cli.StringFlag{
			Name:   "key",
			Value:  "it's a secrect",
			Usage:  "pre-shared secret between client and server",
			EnvVar: "KCPTUN_KEY",
		},
		cli.StringFlag{
			Name:  "crypt",
			Value: "aes",
			Usage: "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none",
		},
		cli.StringFlag{
			Name:  "mode",
			Value: "fast",
			Usage: "profiles: fast3, fast2, fast, normal, manual",
		},
		cli.IntFlag{
			Name:  "mtu",
			Value: 1350,
			Usage: "set maximum transmission unit for UDP packets",
		},
		cli.IntFlag{
			Name:  "sndwnd",
			Value: 1024,
			Usage: "set send window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "rcvwnd",
			Value: 1024,
			Usage: "set receive window size(num of packets)",
		},
		cli.IntFlag{
			Name:  "datashard,ds",
			Value: 10,
			Usage: "set reed-solomon erasure coding - datashard",
		},
		cli.IntFlag{
			Name:  "parityshard,ps",
			Value: 3,
			Usage: "set reed-solomon erasure coding - parityshard",
		},
		cli.IntFlag{
			Name:  "dscp",
			Value: 0,
			Usage: "set DSCP(6bit)",
		},
		cli.BoolFlag{
			Name:  "nocomp",
			Usage: "disable compression",
		},
		cli.BoolFlag{
			Name:   "acknodelay",
			Usage:  "flush ack immediately when a packet is received",
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nodelay",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "interval",
			Value:  50,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "resend",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:   "nc",
			Value:  0,
			Hidden: true,
		},
		cli.IntFlag{
			Name:  "sockbuf",
			Value: 4194304, // socket buffer size in bytes
			Usage: "per-socket buffer in bytes",
		},
		cli.IntFlag{
			Name:  "smuxver",
			Value: 1,
			Usage: "specify smux version, available 1,2",
		},
		cli.IntFlag{
			Name:  "smuxbuf",
			Value: 4194304,
			Usage: "the overall de-mux buffer in bytes",
		},
		cli.IntFlag{
			Name:  "streambuf",
			Value: 2097152,
			Usage: "per stream receive buffer in bytes, smux v2+",
		},
		cli.IntFlag{
			Name:  "keepalive",
			Value: 10, // nat keepalive interval in seconds
			Usage: "seconds between heartbeats",
		},
		cli.StringFlag{
			Name:  "snmplog",
			Value: "",
			Usage: "collect snmp to file, aware of timeformat in golang, like: ./snmp-20060102.log",
		},
		cli.IntFlag{
			Name:  "snmpperiod",
			Value: 60,
			Usage: "snmp collect period, in seconds",
		},
		cli.BoolFlag{
			Name:  "pprof",
			Usage: "start profiling server on :6060",
		},
		cli.StringFlag{
			Name:  "log",
			Value: "",
			Usage: "specify a log file to output, default goes to stderr",
		},
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "to suppress the 'stream open/close' messages",
		},
		cli.BoolFlag{
			Name:  "tcp",
			Usage: "to emulate a TCP connection(linux)",
		},
		cli.StringFlag{
			Name:  "c",
			Value: "", // when the value is not empty, the config path must exists
			Usage: "config from json file, which will override the command from shell",
		},
	}
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		config.Redis = c.String("redis")
		config.TokenLength = c.Int("tokenlength")
		config.Bandwidth = c.Int("bandwidth")
		config.AuditorMgr = NewTrafficAuditor()
		config.TrafficUPdateUrl = c.String("trafficupdateurl")

		config.Listen = c.String("listen")
		config.Target = c.String("target")
		config.Key = c.String("key")
		config.Crypt = c.String("crypt")
		config.Mode = c.String("mode")
		config.MTU = c.Int("mtu")
		config.SndWnd = c.Int("sndwnd")
		config.RcvWnd = c.Int("rcvwnd")
		config.DataShard = c.Int("datashard")
		config.ParityShard = c.Int("parityshard")
		config.DSCP = c.Int("dscp")
		config.NoComp = c.Bool("nocomp")
		config.AckNodelay = c.Bool("acknodelay")
		config.NoDelay = c.Int("nodelay")
		config.Interval = c.Int("interval")
		config.Resend = c.Int("resend")
		config.NoCongestion = c.Int("nc")
		config.SockBuf = c.Int("sockbuf")
		config.SmuxBuf = c.Int("smuxbuf")
		config.StreamBuf = c.Int("streambuf")
		config.SmuxVer = c.Int("smuxver")
		config.KeepAlive = c.Int("keepalive")
		config.Log = c.String("log")
		config.SnmpLog = c.String("snmplog")
		config.SnmpPeriod = c.Int("snmpperiod")
		config.Pprof = c.Bool("pprof")
		config.Quiet = c.Bool("quiet")
		config.TCP = c.Bool("tcp")

		if c.String("c") != "" {
			//Now only support json config file
			err := parseJSONConfig(&config, c.String("c"))
			checkError(err)
		}

		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}
		log.Println("redis:", config.Redis)
		log.Println("auth token length:", config.TokenLength)
		log.Println("VPS max bandwidth:", config.Bandwidth)
		log.Println("user raffic persistence url:", config.TrafficUPdateUrl)

		log.Println("version:", VERSION)
		log.Println("smux version:", config.SmuxVer)
		log.Println("listening on:", config.Listen)
		log.Println("target:", config.Target)
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("smuxbuf:", config.SmuxBuf)
		log.Println("streambuf:", config.StreamBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("pprof:", config.Pprof)
		log.Println("quiet:", config.Quiet)
		log.Println("tcp:", config.TCP)

		// parameters check
		if config.SmuxVer > maxSmuxVer {
			log.Fatal("unsupported smux version:", config.SmuxVer)
		}

		log.Println("initiating key derivation")
		pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
		log.Println("key derivation done")
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "sm4":
			block, _ = kcp.NewSM4BlockCrypt(pass[:16])
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}

		go generic.SnmpLogger(config.SnmpLog, config.SnmpPeriod)
		if config.Pprof {
			go http.ListenAndServe(":6060", nil)
		}

		// main loop
		var wg sync.WaitGroup
		loop := func(lis *kcp.Listener) {
			defer wg.Done()
			if err := lis.SetDSCP(config.DSCP); err != nil {
				log.Println("SetDSCP:", err)
			}
			if err := lis.SetReadBuffer(config.SockBuf); err != nil {
				log.Println("SetReadBuffer:", err)
			}
			if err := lis.SetWriteBuffer(config.SockBuf); err != nil {
				log.Println("SetWriteBuffer:", err)
			}

			for {
				if conn, err := lis.AcceptKCP(); err == nil {
					log.Println("remote address:", conn.RemoteAddr())
					conn.SetStreamMode(true)
					conn.SetWriteDelay(false)
					conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
					conn.SetMtu(config.MTU)
					conn.SetWindowSize(config.SndWnd, config.RcvWnd)
					conn.SetACKNoDelay(config.AckNodelay)

					if config.NoComp {
						go handleMux(conn, &config)
					} else {
						go handleMux(generic.NewCompStream(conn), &config)
					}
				} else {
					log.Printf("%+v", err)
				}
			}
		}

		auditTraffic := func(){
			ticker := time.Tick(time.Second*31)// 每N秒执行持久化流量到redis的工作
			ticker2 := time.Tick(time.Second*33)//每10分钟做一次流量持久化到数据库
			for{
				select{
				case traffic := <- config.AuditorMgr.trafficCh:   //实际发生流量记录到内存
					t := strings.Split(traffic, ",")
					email := t[0]
					upBytes, _ := strconv.ParseInt(t[1], 10, 64)
					downBytes, _ :=strconv.ParseInt(t[2], 10, 64)
					config.AuditorMgr.UpdateTraffic(email, upBytes, downBytes)
				case  <- ticker://从内存放入redis,同时清空内存记录
					redisServ := NewRedisServer(config.Redis)
					defer redisServ.Server.Close()
					for email, auditor := range config.AuditorMgr.auditor{
						log.Printf("%s: up=%d, down=%d", email, auditor.UpstreamTrafficByte, auditor.DownstreamTrafficByte)
						if auditor.UpstreamTrafficByte>0{
							redisServ.Server.IncrBy(context.Background(), email+"_upBytes", auditor.UpstreamTrafficByte)
						}
						if auditor.DownstreamTrafficByte>0 {
							redisServ.Server.IncrBy(context.Background(), email+"_downBytes", auditor.DownstreamTrafficByte)
						}
						auditor.UpstreamTrafficByte = 0
						auditor.DownstreamTrafficByte = 0
					}
					case <- ticker2://批量从redis放入数据库.
						redisServ := NewRedisServer(config.Redis)
						defer redisServ.Server.Close()
						trafficInfo := []string{}
						emails := [] string{}
						for email, _ := range config.AuditorMgr.auditor{
							emails = append(emails, email)
							tk,_ := redisServ.Server.Get(context.Background(), email+"_token").Result()// email对应的token
							upTraffic,_ := redisServ.Server.Get(context.Background(), email+"_upBytes").Result()// 上行流量
							downTraffic,_ := redisServ.Server.Get(context.Background(), email+"_downBytes").Result()//下行流量
							values := []string{tk, upTraffic, downTraffic}
							trafficInfo = append(trafficInfo, strings.Join(values, ","))
						}
						//获取到所有参数之后，上报到数据库
						data := strings.Join(trafficInfo, ",")
						c := new(http.Client)
						req := request.NewRequest(c)
						if resp, err := req.PostForm(config.TrafficUPdateUrl, map[string]string{"data":data}); err==nil{//TODO
							if j, err := resp.Json(); err==nil{
								if code, err := j.Get("code").Int(); err==nil && code==0{
									//上报成功，清空redis。然后 TODO 去除多余的auditor
									for _, em :=  range emails{
										redisServ.Server.Del(context.Background(), em+"_upBytes").Err()
										redisServ.Server.Del(context.Background(), em+"_downBytes").Err()
									}
								}
								if trafficStatistics, err := j.Get("status").Array();err==nil{//返回数组的数组[[email, totalTraffic, usedTraffic],[]]
									for _, v := range trafficStatistics{
										astring := make([]string, len(v.([]interface{})))
										for i, x:= range v.([]interface{}){
											astring[i] = x.(string)
										}
										email, total, used := astring[0], astring[1], astring[2]
										log.Println(email, total, used)
										totalInt, _ := strconv.ParseInt(total, 10, 64)
										usedInt, _ := strconv.ParseInt(used, 10, 64)
										e := redisServ.Server.Set(context.Background(), email+"_total_gb", totalInt, -1).Err()
										e2 := redisServ.Server.Set(context.Background(), email+"_used_kb", usedInt, -1).Err()
										log.Println(e, e2)
									}
								}
							}
							defer resp.Body.Close()  // Don't forget close the response body
						}

				}
			}
		}

		if config.TCP { // tcp dual stack
			if conn, err := tcpraw.Listen("tcp", config.Listen); err == nil {
				lis, err := kcp.ServeConn(block, config.DataShard, config.ParityShard, conn)
				checkError(err)
				wg.Add(1)
				go loop(lis)
			} else {
				log.Println(err)
			}
		}

		// udp stack
		lis, err := kcp.ListenWithOptions(config.Listen, block, config.DataShard, config.ParityShard)
		checkError(err)
		wg.Add(1)
		go loop(lis)
		go auditTraffic()
		wg.Wait()
		return nil
	}
	myApp.Run(os.Args)
}
