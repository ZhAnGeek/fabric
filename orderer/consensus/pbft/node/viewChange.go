package node

import (
	"github.com/hyperledger/fabric/orderer/consensus/pbft/message"
	"github.com/hyperledger/fabric/orderer/consensus/pbft/server"
	"log"
	"time"
)

func (n *Node) viewChangeExpire() {
	timeout := time.After(time.Second * 5)
	select {
		case <- timeout:
			log.Printf("commit failed, view change")
			n.sendViewChangeMessage()
		case <- n.noViewChangeNotify:
			log.Printf("commit successed, no view change")
	}
}

func (n *Node) sendViewChangeMessage() {
	content, _, _ := message.NewViewChangeMsg(n.id, n.view.NextView())
	n.BroadCast(content, server.ViewChangeEntry)
}

func (n *Node) viewChangeRecvThread() {
	for {
		select {
			case msg := <- n.viewChangeRecv:
				if n.buffer.IsTrueOfViewChangeMsg(msg.Digest, n.cfg.FaultNum){
					n.newViewPrimary(msg.View)
				}
		}
	}
}

func (n *Node) newViewPrimary(view message.View) {
	n.view = view
}