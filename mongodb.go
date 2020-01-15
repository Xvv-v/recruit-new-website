//package mongodb

package main

import (
	"errors"
	"log"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"github.com/xvv-v/rabbitmq"
)

var session *mgo.Session

//Test 测试
type Test struct {
	Name string
	Age  int
	Sex  string
	rabbit *rabbitmq.Connect
}

//Connect 连接
type Connect struct {
	collect *mgo.Collection
}

func init() {
	var err error
	session, err = mgo.Dial("127.0.0.1:27017") //连接
	if err != nil {
		log.Println("mongodb连接失败：", err)
	}
	session.SetMode(mgo.Monotonic, true)
}

//设置集合
func connect(db, collection string) *mgo.Collection {
	c := session.DB(db).C(collection)
	return c
}

// 检查错误
func failOnErr(msg string, err error) {

	if err != nil {
		log.Println(msg, err)
	}
}

//SwapOne 转换
func (c *Connect) SwapOne(name, value string) map[string]interface{} {

	return bson.M{name: value}
}

//SwapAnd 复合
func (c *Connect) SwapAnd(name1, name2, value1, value2 string) map[string]interface{} {

	return bson.M{name1: value1, name2: value2}
}

//SwapOr 或者
func (c *Connect) SwapOr(name1, name2, value1, value2 string) map[string]interface{} {

	return bson.M{"$or": []bson.M{bson.M{name1: value1}, bson.M{name2: value2}}}
}

//接受消息队列的数据
func receiveMsg()  {
	
	//b:=
}

//Add 添加
func (c *Connect) Add(dname, cname string, seletor interface{}) error {

	//session和collection
	c.collect = connect(dname, cname)
	err := c.collect.Insert(&seletor)
	if err != nil {
		return errors.New("添加错误")
	}
	return nil
}

//Del 删除
func (c *Connect) Del(dname, cname string, selector interface{}) error {

	//session和collection
	c.collect = connect(dname, cname)
	err := c.collect.Remove(selector)
	if err != nil {
		return errors.New("删除错误")
	}
	return nil
}

//Change 修改
func (c *Connect) Change(dname, cname string, selector, update interface{}) error {

	//session和collection
	cc := connect(dname, cname)
	err := cc.Update(selector, update)
	if err != nil {
		return errors.New("修改错误")
	}
	return nil
}

//FindOne 单个查询
func (c *Connect) FindOne(dname, cname string, query, result interface{}) error {

	//session和collection
	c.collect = connect(dname, cname)
	err := c.collect.Find(query).One(result)
	if err != nil {
		return errors.New("单个查询错误")
	}
	return nil
}

//FindAll 多行查询
func (c *Connect) FindAll(dname, cname string, query, result interface{}) error {

	//session和collection
	cc := connect(dname, cname)
	err := cc.Find(query).All(result)
	if err != nil {
		return errors.New("多行查询错误")
	}
	return nil
}

func main() {

	c := new(Connect)
	//test := []Test{}
	test := Test{}
	c.FindOne("forum", "test", c.SwapOne("name", "小文"), &test)

	// for _, v := range test {
	// 	fmt.Println(v.Name)
	// 	fmt.Println(v.Age)
	// 	fmt.Println(v.Sex)
	// }

	fmt.Println(test.Name)
	fmt.Println(test.Age)
	fmt.Println(test.Sex)

	//c.del("forum", "test", bson.M{"name": "小宋"})
	//c.change("forum", "test", bson.M{"name": "小孟"}, bson.M{"$set": bson.M{"name": "小文", "age1": 8, "sex": "女"}})
}
