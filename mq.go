//package rabbitmq
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/streadway/amqp"
)

const (
	//Direct 直行交换机
	Direct = "direct"
	//Fanout 扇形交换机
	Fanout = "fanout"
	//Topic 主题交换机
	Topic = "topic"
	//Headers 首部交换机
	Headers = "headers"
	//AllUser 所用用户
	AllUser = "all"
)

//Connect 测试
type Connect struct {
	conn     *amqp.Connection //连接
	ch       *amqp.Channel    //通道
	body     chan []byte
	exchange []Exchange            //交换机
	myqueue  amqp.Queue            //创建的队列
	queue    map[string]amqp.Queue //队列、名字map
}

//Exchange 交换机
type Exchange struct {
	qname []string //绑定的队列
	ename string   //交换机名
	key   string   //routing-key
	etype string   //交换机类型
}

//NewConnect 连接
func NewConnect() *Connect {

	var c = new(Connect)
	var err error
	c.conn, err = amqp.Dial("amqp://guest:guest@localhost:5672/")
	if err != nil {
		log.Println("创建链接错误", err)
		return nil
	}
	c.ch, err = c.conn.Channel()
	if err != nil {
		log.Println("创建通道错误：", err)
		return nil
	}
	c.queue = make(map[string]amqp.Queue)
	c.exchange = make([]Exchange, 50)
	c.body = make(chan []byte)
	return c
}

//NewExChange 创建交换机实例
func NewExChange(ename, key, etype string) Exchange {

	return Exchange{
		qname: make([]string, 10),
		ename: ename,
		key:   key,
		etype: etype,
	}
}

//声明队列
func (c *Connect) createQueue(name string) amqp.Queue {

	queue, err := c.ch.QueueDeclare(
		name,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Println("创建队列失败：", err)
	}
	c.queue[name] = queue
	return queue
}

//声明交换机
func (c *Connect) createExcahnge(name, key, etype string) {

	err := c.ch.ExchangeDeclare(
		name,  //交换机名
		etype, //交换机类型
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Println("声明交换机失败：", err)
	}
	c.exchange = append(c.exchange, NewExChange(name, key, etype))
}

//绑定
func (c *Connect) bind(qname, ename, key string) {

	err := c.ch.QueueBind(
		qname, //队列名，name
		key,   //binding-key 交换类型，一个交换机可以绑定多个队列
		ename, //交换机名
		false,
		nil,
	)
	if err != nil {
		log.Println("绑定交换机队列失败：", err)
	}
}

//SendMsg 发送消息 参数：发送的消息([]byte类型)，交换机名称，routing-key，交换机类型
func (c *Connect) SendMsg(msg []byte, ename, key, etype string) {

	//如果没有该交换机，就创建一个
	mark := 0
	for _, v := range c.exchange {
		if v.ename == ename {
			mark = 1
			break
		}
	}
	if mark == 0 {
		c.createExcahnge(ename, key, etype)
	}

	err := c.ch.Publish(
		ename, //交换机名
		key,   //routing-key
		false,
		false,
		amqp.Publishing{
			DeliveryMode: amqp.Persistent, //将消息持久化
			ContentType:  "text/plain",
			Body:         msg,
		},
	)
	if err != nil {
		log.Println("发送消息失败：", err)
		return
	}
	fmt.Println("发送成功！")
}

//Receive 接收消息 参数：队列名，交换机名，routing-key，返回消息为[]byte类型
func (c *Connect) Receive(qname, ename, key string) []byte {

	mark := 0
	//如果没有该队列，就创建一个
	for k := range c.queue {
		if k == qname {
			mark = 1
			break
		}
	}
	if mark == 0 {
		c.createQueue(qname)
	}

	//绑定
	c.bind(qname, ename, key)

	//公平调度
	err := c.ch.Qos(
		1, // prefetch count,prefetch count为 1 时，
		//只有当消费者消费完消息并返回ack确认后RabbitMQ才会给其分发消息，否则只会将消息分发给其他空闲状态的消费者
		0,     // prefetch size
		false, // global
	)
	if err != nil {
		log.Println(err)
	}

	msg, err := c.ch.Consume(
		qname, //队列名
		"",    // consumer
		false,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Println("接收消息失败：", err)
		//return nil
	}

	// go func() {

	// 	for b := range msg {
	// 		c.body<-b.Body
	// 		b.Ack(false)
	// 	}
	// }()

	b := <-msg
	fmt.Printf("msg：%s\n", b.Body)
	b.Ack(false)
	return b.Body

}

var connect1 = NewConnect()
var connect2 = NewConnect()

func test() {

	for {
		body := connect1.Receive("test1", "test", "test1")
		fmt.Printf("body：%s\n", body)
		b <- body
	}
}

func ttest() {

	for {
		select {
		case bb, ok := <-b:
			if !ok {
				return
			}
			fmt.Printf("bb：%s\n", bb)
		}
	}
}

var b = make(chan []byte)

func main() {

	go ttest()
	go test()
	connect1.SendMsg([]byte("test111"), "test", "test1", Direct)
	connect1.SendMsg([]byte("test222"), "test", "test1", Direct)
	// connect1.SendMsg([]byte("test333"), "test", "test2", Direct)
	// connect1.SendMsg([]byte("test444"), "test", "test2", Direct)
	// body1 := connect2.Receive("test1", "test", "test1")
	// fmt.Printf("%s\n", body1)
	// body2 := connect2.Receive("test1", "test", "test1")
	// fmt.Printf("%s\n", body2)
	// body3 := connect1.Receive("test2", "test", "test2")
	// fmt.Printf("%s\n", body3)
	// body4 := connect1.Receive("test2", "test", "test2")
	// fmt.Printf("%s\n", body4)
	//connect.Receive("test", "test", "test")
	// msg1 := connect.Receive("test1", "test", "test1")
	// msg2 := connect.Receive("test2", "test", "test2")
	// go func() {
	// 	fmt.Println("匿名线程开启")
	// 	for b1 := range msg1 {
	// 		fmt.Printf("test1：%s\n", b1.Body)
	// 		b1.Ack(false)
	// 		time.Sleep(time.Second)
	// 	}
	// }()
	// go func() {
	// 	fmt.Println("匿名线程开启")
	// 	for b2 := range msg2 {
	// 		fmt.Printf("test2：%s\n", b2.Body)
	// 		b2.Ack(false)
	// 		time.Sleep(time.Second)
	// 	}
	// }()
	time.Sleep(1 * time.Second)
	fmt.Println("结束")
	return
}
