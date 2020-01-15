package main

import (
	"encoding/json"
	"fmt"
	"github.com/xvv-v/rabbitmq"
	"log"
	"net/http"
)

//RegisterMSG 注册信息
type RegisterMSG struct {
	Username string `json:"username,omitempty"`
	Type     string `json:"type,omitempty"`
	Account  string `json:"account,omitempty"`
	Password string `json:"password,omitempty"`
}

//ReturnMSG 返回消息
type ReturnMSG struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

//ResultMSG 查询结果
type ResultMSG struct {
	Check bool `json:"check,omitempty"`
}

//Mysql 缓存
type Mysql struct {
	Operation string   `json:"operation,omitempty"`
	Table     string   `json:"table,omitempty"`
	Result    []string `json:"result,omitempty"`
	Condition []string `json:"condition,omitempty"`
}

//Register 注册
type Register struct {
	remsg   RegisterMSG
	ret     ReturnMSG
	res     ResultMSG
	mysql   Mysql
	connect *rabbitmq.Connect
}

//NewRegister 创建实例
func NewRegister() *Register {

	return &Register{
		remsg:   RegisterMSG{},
		ret:     ReturnMSG{},
		res:     ResultMSG{},
		mysql:   Mysql{Result: make([]string, 100), Condition: make([]string, 100)},
		connect: rabbitmq.NewConnect(),
	}
}

//判断账号是否存在
func (re *Register) checkExit() bool {

	re.mysql.Operation = "select"
	re.mysql.Table = "register"
	re.mysql.Result = append(re.mysql.Result, "*")
	re.mysql.Condition = append(re.mysql.Condition, "account")
	re.mysql.Condition = append(re.mysql.Condition, re.remsg.Account)
	re.mysql.Condition = append(re.mysql.Condition, "type")
	re.mysql.Condition = append(re.mysql.Condition, re.remsg.Type)
	b, _ := json.Marshal(re.mysql)
	re.connect.SendMsg(b, "database", "register", rabbitmq.Direct)
	//接收消息
	body := re.connect.Receive("register1", "database", "register")
	err := json.Unmarshal(body, &re.res)
	if err != nil {
		log.Println("检查账号是否注册解析json出错", err)
	}
	if re.res.Check == true {
		//账号已存在
		return true
	}
	//账号不存在，可以注册
	return false
}

//注册
func register(w http.ResponseWriter, r *http.Request) {

	re := NewRegister()
	json.NewDecoder(r.Body).Decode(&re.remsg)
	if ok := re.checkExit(); !ok {
		//账号不存在,可以注册
		//向缓存服务通知
		re.mysql.Operation = "insert into"
		re.mysql.Table = "register"
		re.mysql.Condition = append(re.mysql.Condition, re.remsg.Account)
		re.mysql.Condition = append(re.mysql.Condition, re.remsg.Password)
		re.mysql.Condition = append(re.mysql.Condition, re.remsg.Type)
		b, _ := json.Marshal(re.mysql)
		re.connect.SendMsg(b, "database", "register", rabbitmq.Direct)
		//设置响应信息
		re.ret.Message = "注册成功！"
	}
	//设置相应信息
	re.ret.Message = "该账号已注册"
	re.ret.Code = http.StatusOK
	//响应
	w.Header().Set("Content-Type", "application/json")
	b, err := json.Marshal(&re.ret)
	if err != nil {
		log.Println("注册服务响应json编码错误", err)
		return
	}
	w.Write(b)
	w.WriteHeader(http.StatusOK)
}

func main() {

	fmt.Println("注册服务 8082")
	http.HandleFunc("/register", register)
	log.Fatal(http.ListenAndServe(":8082", nil))
}
