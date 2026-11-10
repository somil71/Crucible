package main

import (
	"os"
)

func main() {
	ch := make(chan int, 1)
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}
	ch <- sum

	val := <-ch
	if val != 499500 {
		os.Exit(1)
	}
	os.Exit(0)
}
