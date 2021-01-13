package node

import (
	"bytes"
	"encoding/json"
	"github.com/hyperledger/fabric/orderer/consensus/pbft/message"
	"github.com/hyperledger/fabric/orderer/consensus/pbft/server"
	"log"
	"net/http"
	"time"
)

func (n *Node) SendPrimary(msg *message.Request) {
	content, err := json.Marshal(msg)
	if err != nil {
		log.Printf("error to marshal json")
		return
	}
	log.Printf(n.table[n.GetPrimary()] + server.RequestEntry)
	go SendPost(content, n.table[n.GetPrimary()] + server.RequestEntry)
}

func (n *Node) BroadCast(content []byte, handle string) {
	for k, v := range n.table {
		// do not send to my self
		if k == n.id {
			continue
		}
		go SendPost(content, v + handle)
	}
}

func (n *Node) Primary(content []byte, handle string) {
	if n.IsPrimary() {
		return
	}
	go SendPost(content, n.table[n.GetPrimary()] + handle)
}

func (n *Node) GetAck(content []byte, handle string, callback func ()) {
	ticker := time.NewTicker(time.Millisecond * 100)
	for {
		select {
			case <-ticker.C:
				if resp, err := GetAck(content, n.table[n.GetPrimary()] + handle); err != nil {
					continue
				} else if resp.StatusCode == http.StatusOK {
					callback()
					break
				} else {
					log.Printf("recognize as byzantine")
					break
				}
		}
	}
}

func SendPost(content []byte, url string) {
	buff := bytes.NewBuffer(content)
	if _, err := http.Post(url, "application/json", buff); err != nil {
		log.Printf("[Send] send to %s error: %s", url, err)
	}
}

func GetAck(content []byte, url string) (resp *http.Response, err error) {
	buff := bytes.NewBuffer(content)
	if resp, err := http.Post(url, "application/json", buff); err != nil {
		log.Printf("[Send] send to %s error: %s", url, err)
	} else {
		return resp, err
	}
	return resp, err
}

