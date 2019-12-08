package handlejson

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
)

//GetJSON 解码json
func GetJSON(body io.ReadCloser, value interface{}) {

	if body != nil {
		err := json.NewDecoder(body).Decode(&value)
		if err != nil {
			log.Fatal("解析json出错：", err)
		}
	}
	log.Fatal("请求主体为空：")
}

//SetJSON 编码json
func SetJSON(value interface{}) *bytes.Buffer {

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(value)
	return b
}

//GetByteJSON 从[]byte中解码json
func GetByteJSON(body io.ReadCloser, value interface{}) {

	b, err := ioutil.ReadAll(body)
	if err != nil {
		log.Fatal("读取第二步响应错误：", err)
	}
	//解码json
	if err = json.Unmarshal(b, &value); err != nil {
		log.Fatal("解析第二步请求响应json错误：", err)
	}
}

//SetByteJSON 编码json到一个[]byte类型中，为了发送响应
func SetByteJSON(value interface{}) []byte {

	b, err := json.Marshal(&value)
	if err != nil {
		log.Fatal("编码json错误：", err)
	}
	return b
}
