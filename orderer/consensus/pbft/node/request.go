package node

import (
	"github.com/hyperledger/fabric/orderer/consensus/pbft/message"
	"log"
)

func (n *Node) requestRecvThread() {
	log.Printf("[Node] start recv the request thread")
	for {
		msg := <- n.requestRecv
		// check is primary
		log.Printf("[Node] msg := %v", n.IsPrimary())
		log.Printf("[Node] msg := %v", n.GetPrimary())
		log.Printf("[Node] msg := %v", message.Identify(n.view))
		if !n.IsPrimary() {
			if n.lastReply.Equal(msg) {
				// TODO just reply
			}else {
				// TODO just send it to primary
			}
			// TODO now just reject
			continue
		}
		n.buffer.AppendToRequestQueue(msg)
		n.prePrepareSendNotify <- true
	}
}
