package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"time"

	"gopkg.in/yaml.v2"
)

//SendSMS 发送验证码接口
type SendSMS interface {

	//请求
	SenRequest()
	//验证码
	GetCode()
}

//Telephone 手机号
type Telephone struct {
	Phonenum string `json:"telephone,omitempty"`
}

//Verification 验证码
type Verification struct {
	Code string `json:"code"`
	Message      string `json:"message,omitempty"`
	Verification string `json:"verification,omitempty"`
}

//Receive 云片返回
type Receive struct {
	Code   string `json:"code,omitempty"`
	Msg    string `json:"msg,omitempty"`
	Count  string `json:"count,omitempty"`
	Fee    string `json:"fee,omitempty"`
	Unit   string `json:"unit,omitempty"`
	Mobile string `json:"mobile,omitempty"`
	Sid    string `json:"sid,omitempty"`
}

//Send 发送
type Send struct {
	Apikey string `json:"apikey,omitempty"`
	Mobile string `json:"mobile,omitempty"`
	Text   string `json:"text,omitempty"`
}

//SMSConfig 短信验证配置文件
type SMSConfig struct {
	Apikey     string `yaml:"apikey"`
	URL        string `yaml:"url"`
	Way        string `yaml:"way"`
	Text       string `yaml:"text"`
	Accept     string `yaml:"Accept"`
	Contentype string `yaml:"Content-Type"`
}

//SMS 短信信息
type SMS struct {
	t    Telephone     //电话号码
	v    Verification  //响应验证码给客户端
	b    *bytes.Buffer //编码后的json
	s    Send          //请求云片
	r    Receive       //云片给的响应
	code string        //验证码
}

var smsconfig=SMSConfig{}

//NewSMS 实例
func NewSMS() *SMS {
	
	return &SMS{
		t: Telephone{},
		v: Verification{},
	}
}

//解析yaml文件
func getConfig() {

	buffer, err := ioutil.ReadFile("smsconfig.yaml")
	if err != nil {

		log.Println("打开yaml文件出错：", err)   
		return
	}
	err = yaml.Unmarshal(buffer, &smsconfig)
	if err != nil {
		log.Println("解析yaml文件出错:\n", err)
	}
}

//GetJSON 解码json
func (sms *SMS)GetJSON(body io.ReadCloser, value interface{}) {

	if body != nil {
		err := json.NewDecoder(body).Decode(&value)
		if err != nil {
			log.Fatal("解析json出错：", err)
		}
	}
	log.Fatal("请求主体为空：")
}

//SetJSON 编码json
func (sms *SMS) SetJSON(value interface{}) {

	json.NewEncoder(sms.b).Encode(value)
}

//GetCode 生成六位数验证码
func (sms *SMS) GetCode() {

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	sms.code = fmt.Sprintf("%06v", rnd.Int31n(1000000))
}

//SendRequest 发送请求
func (sms *SMS) SendRequest() {

	sms.s.Apikey = smsconfig.Apikey
	sms.s.Mobile = sms.t.Phonenum
	sms.s.Text = smsconfig.Text + sms.code
	//编码
	var body *bytes.Buffer
	json.NewEncoder(body).Encode(sms.s)
	//请求
	resp, err := http.Post(smsconfig.URL, "application/json", body)
	if err != nil {

		log.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Println("发送成功")
	//解码
	json.NewDecoder(resp.Body).Decode(&sms.r)
	return
}

//处理器函数
func sendsms(w http.ResponseWriter, r *http.Request) {

	sms:=NewSMS()
	//读取请求
	json.NewDecoder(r.Body).Decode(&sms.t)
	//发短信
	sms.SendRequest()
	//响应
	sms.v.Verification = sms.r.Code
	sms.SetJSON(sms.v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(sms.b.Bytes())
}

func main() {

	getConfig()
	fmt.Println("短信服务")
	http.HandleFunc("/sms", sendsms)
	log.Println(http.ListenAndServe(":8085", nil))
}
