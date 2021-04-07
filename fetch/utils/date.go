package utils

import "time"

const YYYYMMDDHH24MISS = "2006-01-02-15:04:05"

func Transfer2Time(t string) (time.Time, error) {
	return time.ParseInLocation(YYYYMMDDHH24MISS, t, time.Local)
}

func GetNowTime() string {
	return time.Now().Format(YYYYMMDDHH24MISS)
}
