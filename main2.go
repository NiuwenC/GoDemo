package main

import (
	"encoding/json"
	"fmt"
)

func main() {
	str, err := json.Marshal("aaaa")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(str)
}
