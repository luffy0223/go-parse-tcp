package pcapfile

import (
	"fmt"
	"io/ioutil"
)

func ReadFile(fileName string)(result string)  {
	f,err:= ioutil.ReadFile(fileName)
	if err!=nil{
		fmt.Println("read fail")
	}

	return string(f)
}

func Parsepcap(){

}
