package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/xvv-v/rabbitmq"
	"gopkg.in/yaml.v2"
)

//UserMSG 用户资料
type UserMSG struct {
	UserID     string `json:"userid,omitempty"`
	Username   string `json:"username,omitempty"`
	Telenumber string `json:"telenumber,omitempty"`
	Email      string `json:"e_mail,omitempty"`
	Password   string `json:"password,omitempty"`
	WeChat     string `json:"wechat,omitempty"`
	QQ         string `json:"qq,omitempty"`
	Jtoken     string `json:"jtoken,omitempty"`
}

//LoginMSG 账号密码
type LoginMSG struct {
	Accountype string `json:"type,omitempty"`
	Account    string `json:"account,omitempty"`
	Password   string `json:"password,omitempty"`
}

//ReqToken 登录信息
type ReqToken struct {
	UserID   string `json:"userid,omitempty"`
	Username string `json:"username,omitempty"`
}

//Token 认证信息
type Token struct {
	State     string `json:"state,omitempty"`
	UserToken string `json:"token,omitempty"`
}

//SMS 手机号
type SMS struct {
	Telephone string `json:"telephone,omitempty"` //手机号
}

//WeChatAuthentication 微信登陆授权
type WeChatAuthentication struct {
	Containerid string `json:"cid,omitempty"` //放置微信二维码的容器id
}

//QQLogin qq登录
type QQLogin struct {
	State string `json:"qqstate,omitempty"` //状态
}

//QQAuthentication qq授权传参
type QQAuthentication struct {
	AuthorizationCode string `json:"auth,omitempty"`
}

//Code 返回code
type Code struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"msg,omitempty"`
}

//WeChatToken 微信登陆token
type WeChatToken struct {
	AccessToken  string `json:"token,omitempty"`
	ExpiresIn    string `json:"time,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Openid       string `json:"openid,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Unionid      string `json:"unionid,omitempty"` //当且仅当该网站应用已获得该用户的userinfo授权时，才会出现该字段。
}

//QQToken qq授权响应
type QQToken struct {
	AccessToken  string `json:"qqtoken,omitempty"`
	ExpiresIn    string `json:"qqtime,omitempty"` //token有效期
	RefreshToken string `json:"refresh,omitempty"`
}

//QQOpenID 唯一标识
type QQOpenID struct {
	ClientID string `json:"client_id,omitempty"`
	OpenID   string `json:"openid,omitempty"`
}

//WeChatConfig 微信登录配置文件
type WeChatConfig struct {
	Appid      string `yaml:"appid"`
	Appkey     string `yaml:"appkey"`
	Reflecturl string `yaml:"reflect_url"`
	Codeurl    string `yaml:"code_url"`
	Tokenurl   string `yaml:"token_url"`
}

//QQConfig 配置文件
type QQConfig struct {
	Appid      string `yaml:"appid"`
	Appkey     string `yaml:"appkey"`
	Reflecturl string `yaml:"reflect_url"`
	Codeurl    string `yaml:"code_url"`
	Tokenurl   string `yaml:"token_url"`
	Openidurl  string `yaml:"openID"`
}

//Mysql 缓存
type Mysql struct {
	Operation string   `json:"operation,omitempty"`
	Table     string   `json:"table,omitempty"`
	Result    []string `json:"result,omitempty"`
	Condition []string `json:"condition,omitempty"`
}

//Redis 请求缓存服务
type Redis struct {
	Operation string   `json:"operation,omitempty"`
	Key       string   `json:"key,omitempty"`
	Value     []string `json:"value,omitempty"`
}

//Login 登录信息
type Login struct {
	user    UserMSG
	login   LoginMSG
	sms     SMS
	req     ReqToken
	token   Token
	mysql   Mysql
	redis   Redis
	connect *rabbitmq.Connect
}

var qqconfig = new(QQConfig)
var weconfig = new(WeChatConfig)

func init() {

	getConfig(&qqconfig, "qqconfig.yaml")
	getConfig(&weconfig, "wechatconfig.yaml")
}

//NewLogin 创建实例
func NewLogin() *Login {

	return &Login{
		user:    UserMSG{},
		login:   LoginMSG{},
		sms:     SMS{},
		req:     ReqToken{},
		token:   Token{},
		mysql:   Mysql{Result: make([]string, 100), Condition: make([]string, 100)},
		redis:   Redis{Value: make([]string, 100)},
		connect: rabbitmq.NewConnect(),
	}
}

//解析配置文件
func getConfig(value interface{}, name string) {

	buffer, err := ioutil.ReadFile(name)
	if err != nil {

		log.Println("打开yaml文件出错：", err)
		return
	}
	err = yaml.Unmarshal(buffer, &value)
	if err != nil {
		log.Println("解析yaml文件出错:\n", err)
	}
}

//检查账号是否存在
func (login *Login) checkAccount(account, tYpe string) bool {

	login.mysql.Operation = "select"
	login.mysql.Table = "user"
	login.mysql.Result = append(login.mysql.Result, "*")
	if tYpe == "telenumber" {

		login.mysql.Condition = append(login.mysql.Condition, "telenumber")
		login.mysql.Condition = append(login.mysql.Condition, login.login.Account)
	} else {

		login.mysql.Condition = append(login.mysql.Condition, "e_mail")
		login.mysql.Condition = append(login.mysql.Condition, login.login.Account)
	}
	body, err := json.Marshal(login.mysql)
	if err != nil {
		log.Println("编码错误：", err)
	}
	login.connect.SendMsg(body, "cache", "login", rabbitmq.Direct)
	msg := login.connect.Receive("login", "cache", "login")
	json.Unmarshal(msg, &login.user)
	if login.user.UserID != "" {
		return true
	}
	return false
}

//错误响应
func respWrong(w http.ResponseWriter, msg string) {

	b, _ := json.Marshal(Code{Code: 500, Message: msg})
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

//账号密码登录
func accountLogin(w http.ResponseWriter, r *http.Request) {

	//接收到请求创建实例
	login := NewLogin()
	//解析请求
	json.NewDecoder(r.Body).Decode(&login.login)
	login.checkAccount(login.login.Account, login.login.Accountype)
	if login.login.Password == login.user.Password {
		//成功，请求认证服务获取token
		login.req.UserID = login.user.UserID
		login.req.Username = login.user.Username
		b := new(bytes.Buffer)
		json.NewEncoder(b).Encode(login.req)
		resp, err := http.Post("http://192.168.0.106:8088/jtoken", "application/json", b)
		if err != nil {
			log.Println("请求错误：", err)
			respWrong(w, "错误")
			return
		}
		json.NewDecoder(resp.Body).Decode(&login.token)
		login.user.Jtoken = login.token.UserToken
		body, _ := json.Marshal(login.user)
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}
	respWrong(w, "密码错误")
}

//qq登录
func qqLogin(w http.ResponseWriter, r *http.Request) {

	qqLogin := QQLogin{}
	json.NewDecoder(r.Body).Decode(&qqLogin)
	//请求
	resp, err := http.Get(qqconfig.Codeurl+"&client_id="+qqconfig.Appid+"&redirect_uri="+qqconfig.Reflecturl+"&state="+qqLogin.State)
	if err != nil {
		log.Println(err)
		return
	}
	qq := QQAuthentication{}
	json.NewDecoder(resp.Body).Decode(&qq)
	resp,err=http.Get(qqconfig.Tokenurl+"&code="+qq.AuthorizationCode+"&client_id="+qqconfig.Appid+"&client_secret="+qqconfig.Appkey)
	if err != nil {
		log.Println(err)
		return
	}
	qqtoken:=QQToken{}
	json.NewDecoder(resp.Body).Decode(&qqtoken)
	resp,err=http.Get(qqconfig.Openidurl+qqtoken.AccessToken)
	if err != nil {
		log.Println(err)
		return
	}
	qqid:=QQOpenID{}
	json.NewDecoder(resp.Body).Decode(&qqid)
}

//微信登录
func wechatLogin(w http.ResponseWriter, r *http.Request) {

}

//短信登录
func smsLogin(w http.ResponseWriter, r *http.Request) {

	login := NewLogin()
	json.NewDecoder(r.Body).Decode(&login.sms)
	//检查该手机号是否注册
	if ok := login.checkAccount(login.sms.Telephone, "telenumber"); ok {
		b, _ := json.Marshal(login.user)
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}
	respWrong(w, "改手机号未注册")
}

//登出账号
func entry(w http.ResponseWriter, r *http.Request) {

	//接收到请求创建实例
	login := NewLogin()
	//解析请求
	json.NewDecoder(r.Body).Decode(&login.user)
	msg, msgErr := json.Marshal(&Redis{Operation: "del", Key: login.user.UserID})
	if msgErr != nil {
		log.Println("编码错误：", msgErr)
	}
	//缓存服务，将token存入redis
	login.connect.SendMsg(msg, "redis", "del", rabbitmq.Direct)
	body, err := json.Marshal(Code{Code: 200, Message: "退出"})
	if err != nil {
		log.Println("编码错误：", err)
		respWrong(w, "请重试")
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func main() {

	fmt.Println("登录服务 8083")
	http.HandleFunc("/login", accountLogin)
	http.HandleFunc("/qqlogin", qqLogin)
	http.HandleFunc("/wechatlogin", wechatLogin)
	http.HandleFunc("/smslogin", smsLogin)
	http.HandleFunc("/entry", entry)
	log.Fatal(http.ListenAndServe(":8083", nil))
}
