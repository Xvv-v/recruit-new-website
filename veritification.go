package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/xvv-v/rabbitmq"
	"gopkg.in/yaml.v2"
)

//ecdsa 使用 FIPS 186-3 中定义的椭圆曲线数字 签名算法，只作为数字签名

//User 用户信息
type User struct {
	UserID   string `json:"userid,omitempty"`
	Username string `json:"username,omitempty"`
}

//Token 认证信息
type Token struct {
	State     string `json:"state,omitempty"`
	UserToken string `json:"token,omitempty"`
}

//ReturnMSG 返回信息
type ReturnMSG struct {
	Code    int    `json:"code,omitempty"`
	Message string `json:"message,omitemty"`
}

//Statement 缓存服务
type Statement struct {
	SQL      string `json:"sql,omitempty"`
	Exchange string `json:"exchange,omitempty"`
	Queue    string `json:"queue,omitempty"`
	Bindkey  string `json:"bindkey,omitempty"`
}

//Redis 缓存
type Redis struct {
	Operation string `json:"operation,omitempty"`
	Key       string `json:"key,omitempty"`
	Value     int64  `json:"value,omitempty"`
}

//VerConfig 配置文件
type VerConfig struct {
	ECDSAKeyD string `yaml:"keyD"`
	ECDSAKeyX string `yaml:"keyX"`
	ECDSAKeyY string `yaml:"keyY"`
	Signature string `yaml:"signature"` //signature HS256key，暴露给前端
}

//Identification 认证
type Identification struct {
	u       User
	t       Token
	r       ReturnMSG
	connect *rabbitmq.Connect
}

var verconfig = VerConfig{}

//NewIdentity 实例
func NewIdentity() *Identification {

	return &Identification{
		u:       User{},
		t:       Token{},
		r:       ReturnMSG{},
		connect: rabbitmq.NewConnect(),
	}
}

//解析yaml文件
func getConfig() {

	buffer, err := ioutil.ReadFile("verconfig.yaml")
	if err != nil {

		log.Println("打开yaml文件出错：", err)
		return
	}
	err = yaml.Unmarshal(buffer, &verconfig)
	if err != nil {
		log.Println("解析yaml文件出错:\n", err)
	}
}

//failOnErr 错误检查
func failOnErr(msg string, err error) {

	if err != nil {
		log.Println(msg, err)
	}
}

//生成token
func (identity *Identification) getToken() {

	keyD := new(big.Int)
	keyX := new(big.Int)
	keyY := new(big.Int)

	keyD.SetString(verconfig.ECDSAKeyD, 16)
	keyX.SetString(verconfig.ECDSAKeyX, 16)
	keyY.SetString(verconfig.ECDSAKeyY, 16)

	//保存uid和登陆状态
	esClaims := jwt.MapClaims{
		identity.u.UserID: "on",
	}

	esToken := jwt.NewWithClaims(jwt.SigningMethodES256, esClaims)
	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     keyX,
		Y:     keyY,
	}

	privateKey := ecdsa.PrivateKey{D: keyD, PublicKey: publicKey}

	ss, err := esToken.SignedString(&privateKey)
	if err != nil {
		fmt.Println("ES256的token生成签名错误,err：", err)
	}

	//将内层token存入redis，value为过期时间
	msg, msgErr := json.Marshal(&Redis{Operation: "set", Key: identity.u.UserID, Value: time.Now().Add(time.Hour * time.Duration(1)).Unix()})
	if msgErr != nil {
		log.Println("编码错误：", msgErr)
		return
	}
	//缓存服务，将token存入redis
	identity.connect.SendMsg(msg, "redis", "set", rabbitmq.Direct)

	//生成HS256
	hsClaims := jwt.MapClaims{
		"tokenES": ss,
		//解析时，该变量的类型被转换成float64
		"uid":      identity.u.UserID,
		"username": identity.u.Username,
	}

	hsToken := jwt.NewWithClaims(jwt.SigningMethodHS256, hsClaims)
	//加密算法是HS256时，这里的SignedString必须是[]byte（）类型
	hs, err := hsToken.SignedString([]byte(verconfig.Signature))
	if err != nil {
		fmt.Println("token生成签名错误,err：", err)
	}
	identity.t.UserToken = hs
	identity.t.State = "on"
}

//解析token
func (identity *Identification) paraseToken() string {

	//先判断有没有过期
	msg, msgErr := json.Marshal(&Redis{Operation: "get", Key: identity.u.UserID})
	if msgErr != nil {
		log.Println("编码错误：", msgErr)
		return ""
	}
	identity.connect.SendMsg(msg, "redis", "get", rabbitmq.Direct)
	body := identity.connect.Receive("token", "redis", "get")
	if time.Now().Unix() <= int64(binary.BigEndian.Uint64(body)) {
		//过期，重新登录,将这个token删掉
		msg, msgErr := json.Marshal(&Redis{Operation: "del", Key: identity.u.UserID})
		if msgErr != nil {
			log.Println("编码错误：", msgErr)
		}
		//缓存服务，将token存入redis
		identity.connect.SendMsg(msg, "redis", "del", rabbitmq.Direct)
		return "past"
	}

	//先解析HS256
	hstoken, err := jwt.Parse(identity.t.UserToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(verconfig.Signature), nil
	})
	if err != nil {
		fmt.Println("HS256的token解析错误，err：", err)
	}

	hsclaims, ok := hstoken.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("ParseHStoken:claims类型转换失败")
	}

	//解析ES256
	keyX := new(big.Int)
	keyY := new(big.Int)

	keyX.SetString(verconfig.ECDSAKeyX, 16)
	keyY.SetString(verconfig.ECDSAKeyY, 16)

	publicKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     keyX,
		Y:     keyY,
	}

	token, err := jwt.Parse(hsclaims["tokenES"].(string), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return &publicKey, nil
	})
	if err != nil {
		fmt.Println("ES256的token解析错误,err：", err)
	}

	if esclaims, ok := token.Claims.(jwt.MapClaims); ok {
		return esclaims["redisValue"].(string)
	}

	fmt.Println("ParseEStoken:Claims类型转换失败")
	return ""
}

//生成token
func jtoken(w http.ResponseWriter, r *http.Request) {

	identity := NewIdentity()
	//读取请求信息
	json.NewDecoder(r.Body).Decode(&identity.u)

	//生成token，先生成里层，在生成外层
	identity.getToken()

	//响应客户端，将token给客户端
	b, err := json.Marshal(&identity.t)
	failOnErr("编码失败：", err)
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

//解析token
func verify(w http.ResponseWriter, r *http.Request) {

	identity := NewIdentity()
	//读取请求信息
	json.NewDecoder(r.Body).Decode(&identity.t)
	//解析token
	result := identity.paraseToken()
	res := &ReturnMSG{}
	if result == "on" {
		//在线
		res.Code = 200
		res.Message = "ok"
	} else if result == "past" {
		//过期，不在线
		res.Code = 200
		res.Message = "relogin"
	} else {
		res.Code = 500
		res.Message = "wrong"
	}
	//响应客户端
	b, err := json.Marshal(&res)
	if err != nil {
		log.Println("编码错误：", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

func main() {

	getConfig()
	fmt.Println("认证服务")
	http.HandleFunc("/jtoken", jtoken)
	http.HandleFunc("/verify", verify)
	log.Println(http.ListenAndServe(":8088", nil))
}
