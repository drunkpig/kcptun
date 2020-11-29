package main

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

func mainx() {
	options, _ := redis.ParseURL("redis://:@localhost:6379/0")
	rdb := redis.NewClient(options)

	err := rdb.Set(ctx, "key", "value", 0).Err()
	if err != nil {
		panic(err)
	}

	val, err := rdb.Get(ctx, "key").Result()
	if err != nil {
		panic(err)
	}
	fmt.Println("key", val)

	val2, err := rdb.Get(ctx, "key2").Result()
	if err == redis.Nil {
		fmt.Println("key2 does not exist")
	} else if err != nil {
		panic(err)
	} else {
		fmt.Println("key2", val2)
	}
	//total := "100"
	//email := "328233430@qq.com"
	//totalInt, _ := strconv.ParseInt(total, 10, 64)
	e := rdb.Set(context.Background(), "_total_gb", 1000, 10000).Err()
	fmt.Println(e)
	// Output: key value
	// key2 does not exist
}

func te(xx *string) {
	fmt.Println(*xx)
}

func main1() {
	var s string

	s = "abcde"

	te(&s)
}
