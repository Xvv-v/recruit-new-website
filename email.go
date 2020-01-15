package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/smtp"
	"time"

	"github.com/xvv-v/rabbitmq"
	"gopkg.in/yaml.v2"
)

//SendEmail 发送邮件
type SendEmail interface {

	//邮箱号
	SetEmail(em string)
	//发送邮件
	SendEmail()
}

//EmailConfig 邮件配置
type EmailConfig struct {
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Sender   string `yaml:"sender"`
}

//EmailMSG 邮箱信息
type EmailMSG struct {
	EmailNum string `json:"email,omitempty"`
}

//ReturnMSG 返回信息
type ReturnMSG struct {
	Code         int    `jsn:"code"`
	Message      string `json:"message,omitenpty"`
	Verification string `json:"verification,omitempty"`
}

//Email 邮箱信息
type Email struct {
	email   EmailMSG
	ret     ReturnMSG
	msg     chan []byte
	connect *rabbitmq.Connect
}

//NewEmail 实例
func NewEmail() *Email {

	GetConfig()
	return &Email{
		email:   EmailMSG{},
		ret:     ReturnMSG{},
		msg:     make(chan []byte),
		connect: rabbitmq.NewConnect(),
	}
}

var emailconfig = EmailConfig{}

//GetConfig 解析yaml文件
func GetConfig() {

	buffer, err := ioutil.ReadFile("emailConfig.yaml")
	if err != nil {

		log.Println("打开yaml文件出错：", err)
		return
	}
	err = yaml.Unmarshal(buffer, &emailconfig)
	if err != nil {
		log.Println("解析yaml文件出错:\n", err)
	}
}

//GetCode 生成六位验证码
func (email *Email) GetCode() {

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	email.ret.Verification = fmt.Sprintf("%06v", rnd.Int31n(1000000))
}

//SendEmail 发送邮件
func (email *Email) SendEmail() error {

	//设置认证信息
	auth := smtp.PlainAuth("", emailconfig.Sender, emailconfig.Password, "smtp.qq.com")

	//收件人
	to := []string{email.email.EmailNum}

	//获得验证码
	email.GetCode()

	//发送内容
	msg := []byte("To: " + email.email.EmailNum + "\r\n" +
		"Subject: 【仁爱工作室】验证码：\r\n" +
		"\r\n" + email.ret.Verification + "\r\n")
	err := smtp.SendMail(emailconfig.Host, auth, emailconfig.Sender, to, msg)
	if err != nil {
		log.Println("发送错误")
		return err
	}
	fmt.Println("发送成功")
	return nil
}

func email(w http.ResponseWriter, r *http.Request) {

	e := NewEmail()
	json.NewDecoder(r.Body).Decode(&e.email)
	//发送邮件
	serr := e.SendEmail()
	if serr != nil {
		e.ret.Message = serr.Error()
		e.ret.Code = 500
	} else {
		e.ret.Message = "发送成功"
		e.ret.Code = 200
	}
	//响应
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(&e.ret)
	if err != nil {
		log.Println("编码错误", err)
		return
	}
	w.Write(b)
	log.Println("响应完毕")
	return
}

func main() {

	http.HandleFunc("/email", email)
	log.Println(http.ListenAndServe(":8084", nil))
}
