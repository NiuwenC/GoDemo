package main

import (
	"db_demo/struct_test/calendar"
	"fmt"
)

// 接收字段应该被设置为的值，但是输出的时候仍然是0
// 接收器参数接受了一个原值的拷贝。 只是更新了拷贝，在方法退出的时候更新就丢失了

//(d Date)接收了一个Date Struct的拷贝，设置值仅仅是更新拷贝，不是原值，将接收器的值修改为指针来修正SetYear，
//

func main() {
	// 但是日期时间有可能被用户误写，需要校验
	date := calendar.Date{}
	date.SetYear(2019)
	date.SetMonth(20)
	date.SetDay(10)

	fmt.Println(date.Year())
}
