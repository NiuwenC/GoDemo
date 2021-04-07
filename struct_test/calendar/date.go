package calendar

import (
	"errors"
)

// 接收字段应该被设置为的值，但是输出的时候仍然是0
// 接收器参数接受了一个原值的拷贝。 只是更新了拷贝，在方法退出的时候更新就丢失了

//(d Date)接收了一个Date Struct的拷贝，设置值仅仅是更新拷贝，不是原值，将接收器的值修改为指针来修正SetYear，
//
func (d *Date) SetYear(year int) error {
	if year < 1 {
		return errors.New("Invalid year")
	}
	d.year = year
	return nil
}

func (d *Date) SetMonth(month int) {
	d.month = month
}

func (d *Date) SetDay(day int) {
	d.day = day
}

func (d *Date) Year() int {
	return d.year
}

type Date struct {
	year  int
	month int
	day   int
}
