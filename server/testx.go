package main
import (
	"context"
	"github.com/go-redis/redis/v8"
	"fmt"
)

var ctx = context.Background()

func mainx() {
	options, _ := redis.ParseURL("redis://:Gr11disG00d@gw.mkmerich.com:10005/0")
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
	// Output: key value
	// key2 does not exist
}