package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type Page struct {
	URL  string
	Size int
}

func main() {
	mychannel := make(chan Page)
	urls := []string{
		"http://baidu.com",
		"https://mvnrepository.com/",
		"http://lookdiv.com/index/index/indexcodeindex.html",
	}

	for _, url := range urls {
		go responseSize(url, mychannel)
	}

	for i := 0; i < len(urls); i++ {
		page := <-mychannel
		fmt.Printf("%s: %d\n", page.URL, page.Size)
	}

	//time.Sleep(5 * time.Second)

	//go a()
	//go b()
	//time.Sleep(time.Second)
	//fmt.Println("   end main()   ")
	//myChannel := make(chan string)
	//
	//go greeting(myChannel)
	//receivedValue := <- myChannel
	//fmt.Print(receivedValue)

	//channel1 := make(chan string)
	//channel2 := make(chan string)
	//
	//go abc(channel1)
	//go def(channel2)
	//
	//fmt.Print(<- channel1)
	//fmt.Print(<- channel2)
	//fmt.Print(<- channel1)
	//fmt.Print(<- channel2)
	//fmt.Print(<- channel1)
	//fmt.Print(<- channel2)

	//mychannel := make(chan string)
	//go send(mychannel)
	//reportName("receving goroutine, ",5)
	//fmt.Println(<- mychannel)
	//fmt.Println(<- mychannel)

}

func responseSize(url string, mychannel chan Page) {
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close() //main函数退出 就释放网络连接
	body, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatal(err)
	}

	mychannel <- Page{
		URL:  url,
		Size: len(body),
	}
}

func a() {
	for i := 0; i < 50; i++ {
		fmt.Print("a")
	}
}

func b() {
	for i := 0; i < 50; i++ {
		fmt.Print("b")
	}
}

func greeting(myChannel chan string) {
	myChannel <- "hi"

}

func abc(channel chan string) {
	channel <- "a"
	channel <- "b"
	channel <- "c"
}

func def(channel chan string) {
	channel <- "d"
	channel <- "e"
	channel <- "f"
}

func reportName(name string, delay int) {
	for i := 0; i < delay; i++ {
		fmt.Println(name, "sleeping")
		time.Sleep(1 * time.Second)
	}
	fmt.Println(name, "wakes up")
}

func send(myChannel chan string) {
	reportName("sending goroutine ", 2)
	fmt.Println("***sending value***")
	myChannel <- "a"
	fmt.Println("***sending value***")
	myChannel <- "b"

}
