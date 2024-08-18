package main

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |       |C|E|U|A|P|R|S|F|                               |
   | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
   |       |       |R|E|G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           [Options]                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               :
   :                             Data                              :
   :                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

          Note that one tick mark represents one bit position.
*/

/*
   TODO: Append requests with ACK if server replied something i.e is theres'a pending ACK
   TODO: In all states except SYN-SENT, all reset (RST) segments are validated by checking their SEQ fields. A reset is valid if its sequence number is in the window. In the SYN-SENT state (a RST received in response to an initial SYN), the RST is acceptable if the ACK field acknowledges the SYN.
   FIX: detect dup ack
   TODO: Add restransmission support
*/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	IDLE = iota
	LISTEN
	CONNECT
	SYNSENT
	SYNRECV
	ESTABLISHED
	FINWAIT1
	FINWAIT2
	CLOSE
	CLOSEWAIT
	CLOSING
	LASTACK
	TIMEWAIT
	CLOSED
)

var stateToStr = map[uint8]string{
	IDLE:        "IDLE",
	LISTEN:      "LISTEN",
	CONNECT:     "CONNECT",
	SYNSENT:     "SYNSENT",
	SYNRECV:     "SYNRECV",
	ESTABLISHED: "ESTABLISHED",
	FINWAIT1:    "FINWAIT1",
	FINWAIT2:    "FINWAIT2",
	CLOSE:       "CLOSE",
	CLOSEWAIT:   "CLOSEWAIT",
	CLOSING:     "CLOSING",
	LASTACK:     "LASTACK",
	TIMEWAIT:    "TIMEWAIT",
	CLOSED:      "CLOSED",
}

// Convert an integer constant to its string representation
func stateIntToStr(state uint8) string {
	if str, exists := stateToStr[state]; exists {
		return str
	}
	return "UNKNOWN"
}

const (
	IPV4HDRLEN = 20
	TCPHDRLEN  = 20
)

const (
	FIN = 1 << iota
	SYN
	RST
	PSH
	ACK
	URG
	ECE
	CWR
)

type TCPError struct {
	Code    int
	Message string
}

type TCPOption struct {
	Kind   uint8
	Length uint8
	Data   []byte
}

type TCPPack struct {
	Src       uint16
	Dst       uint16
	SeqNum    uint32
	AckNum    uint32
	Offset    uint8 // 4 bits
	Reserved  uint8 // 4 bits
	Flags     uint8
	Window    uint16
	Checksum  uint16 // Kernel will set this if it's 0
	UrgentPtr uint16
	Options   []TCPOption // size(Options) == (DOffset-5)*32; present only when DOffset > 5
	Length    uint16
	Data      []byte
}

type SendVars struct {
	UnAck      uint32
	Next       uint32
	Window     uint16
	UrgentPtr  uint16
	LastSeqNum uint32
	LastAckNum uint32
	InitSeqNum uint32
}

type RecvVars struct {
	Next       uint32
	Window     uint16
	UrgentPtr  uint16
	InitSeqNum uint32
	MSS        uint16
}

type SegVars struct {
	SeqNum    uint32
	AckNum    uint32
	Length    uint16
	Window    uint16
	Flags     uint8
	UrgentPtr uint16
}

type TCPConn struct {
	Fd              int
	LocalAddr       syscall.SockaddrInet4
	RemoteAddr      syscall.SockaddrInet4
	LocalPort       uint16
	RemotePort      uint16
	Hdr             TCPPack
	SendVars        SendVars
	RecvVars        RecvVars
	State           uint8
	CloseListenCh   chan bool
	SendPackCh      chan TCPPack
	SendPackChMu    sync.Mutex
	FastReTransCh   chan uint32
	ReTransSeqNum   uint32
	SendPackCount   uint16
	EffSNDMSS       uint16
	SendPacketQueue *Queue
	RTOTimer        *time.Ticker
}

const logLevel = DEBUG

const (
	OFF  = -1
	WARN = iota
	ERROR
	INFO
	DEBUG
)

const (
	KNRM = "\x1B[0m"
	KRED = "\x1B[31m"
	KGRN = "\x1B[32m"
	KYEL = "\x1B[33m"
	KBLU = "\x1B[34m"
	KMAG = "\x1B[35m"
	KCYN = "\x1B[36m"
	KWHT = "\x1B[37m"

	BRED = "\x1B[1;31m"
	BGRN = "\x1B[1;32m"
	BYEL = "\x1B[1;33m"
	BBLU = "\x1B[1;34m"
	BMAG = "\x1B[1;35m"
	BCYN = "\x1B[1;36m"
	BWHT = "\x1B[1;37m"

	IREDBG = "\x1B[0;91m"
	IGRNBG = "\x1B[0;92m"
	IYELBG = "\x1B[0;93m"
	IBLUBG = "\x1B[0;94m"
	IMAGBG = "\x1B[0;95m"
	ICYNBG = "\x1B[0;96m"
	IWHTBG = "\x1B[0;97m"
)

func flagsIntToStr(value uint8) string {
	flags := ""

	if value&FIN != 0 {
		flags += "FIN, "
	}
	if value&SYN != 0 {
		flags += "SYN, "
	}
	if value&RST != 0 {
		flags += "RST, "
	}
	if value&PSH != 0 {
		flags += "PSH, "
	}
	if value&ACK != 0 {
		flags += "ACK, "
	}
	if value&URG != 0 {
		flags += "URG, "
	}
	if value&ECE != 0 {
		flags += "ECE, "
	}
	if value&CWR != 0 {
		flags += "CWR, "
	}

	// Trim any trailing ", "
	return flags[:len(flags)-2]
}

type Queue struct {
	mu    sync.RWMutex
	items map[uint32]TCPPack
}

func NewQueue() *Queue {
	return &Queue{
		items: make(map[uint32]TCPPack), // Initialize the map here
	}
}

// Enqueue adds an element to the queue.
func (q *Queue) Enqueue(packet TCPPack) {
	q.mu.Lock()
	fmt.Println("Enqueuing key:", packet.SeqNum)
	q.items[packet.SeqNum] = packet
	q.mu.Unlock()
}

// Dequeue removes and returns the front element from the queue.
func (q *Queue) Dequeue(seqNum uint32) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	deleted := false

	for key := range q.items {
		if key < seqNum {
			fmt.Println("Deleted:", key)
			delete(q.items, key)
			deleted = true
		}
	}

	return deleted
}

func (q *Queue) Get(seqNum uint32) (bool, TCPPack) {
	q.mu.RLock()
	packet, ok := q.items[seqNum]
	q.mu.RUnlock()
	return ok, packet
}

func (q *Queue) GetMap() map[uint32]TCPPack {
	q.mu.RLock()
	ret := q.items
	q.mu.RUnlock()
	return ret
}

func (q *Queue) Len() int {
	q.mu.RLock()
	ret := len(q.items)
	q.mu.RUnlock()
	return ret
}

func (conn *TCPConn) log(level int, packet *TCPPack, format string, a ...interface{}) {

	var logLevelString string
	var msgColor string
	switch level {
	case WARN:
		msgColor = KYEL
		logLevelString = fmt.Sprintf("%-6s[WARN] ", msgColor)
	case ERROR:
		msgColor = KRED
		logLevelString = fmt.Sprintf("%s[ERROR] ", msgColor)
	case DEBUG:
		msgColor = KGRN
		logLevelString = fmt.Sprintf("%s[DEBUG] ", msgColor)
	default:
		msgColor = KWHT
		logLevelString = fmt.Sprintf("%-6s[INFO] ", msgColor)

	}
	if level <= logLevel {
		if packet != nil {
			// [PORT -> PORT] [FLAGS] [Seq, Ack, Win, Len] [Status]
			debugString := fmt.Sprintf("%s[%v] %sSTATE[%-11v] %sCONN[%v -> %v] %sFLAGS[%-8v] %s[Seq=%-10v, Ack=%-10v, Win=%-6v, Len=%-4v] .......... %s",
				msgColor, time.Now().UnixMilli(),
				KYEL, stateIntToStr(conn.State),
				IYELBG, packet.Src, packet.Dst,
				IGRNBG, flagsIntToStr(packet.Flags),
				KWHT, packet.SeqNum, packet.AckNum, packet.Window, packet.Length, msgColor)
			debugString2 := fmt.Sprintf(format+"\n", a...)
			debug := logLevelString + debugString + debugString2
			_, _ = fmt.Printf(debug)
		} else {
			debugString := fmt.Sprintf("%s[%v] %sSTATE[%-11v] %sCONN[%v -> %v] \t\t\t\t\t\t\t\t\t      %s.......... %s",
				msgColor, time.Now().UnixMilli(),
				KYEL, stateIntToStr(conn.State),
				IYELBG, conn.LocalPort, conn.RemotePort,
				KWHT, msgColor)
			debugString2 := fmt.Sprintf(format+"\n", a...)
			debug := logLevelString + debugString + debugString2
			_, _ = fmt.Printf(debug)
		}
	}
	return
}

func (err *TCPError) Error() string {
	return fmt.Sprintf("%s[Error code: %d] -> Message: %s", KRED, err.Code, err.Message)
}

func NewTCPError(code int, message string, a ...interface{}) error {
	message = fmt.Sprintf(message, a...)
	return &TCPError{
		Code:    code,
		Message: message,
	}
}

func IPStrtoBytes(ip string) ([4]byte, error) {
	var tcpErr error
	ipBytes := net.ParseIP(ip).To4()
	var resizeIP [4]byte

	if ipBytes != nil {
		copy(resizeIP[:], ipBytes)
	} else {
		tcpErr = NewTCPError(100, "Invalid IPv4 Address")
	}

	return resizeIP, tcpErr
}

// validates and returns IP in bytes
func validateAddrFormat(localIPStr string, remoteIPStr string) ([4]byte, [4]byte, error) {
	var err, tcpErr error
	var localAddrBytes, remoteAddrBytes [4]byte
	localAddrBytes, err = IPStrtoBytes(localIPStr)

	if err != nil {
		tcpErr = NewTCPError(101, "Local IP format error\n%v", err)
		return localAddrBytes, remoteAddrBytes, tcpErr
	}

	remoteAddrBytes, err = IPStrtoBytes(remoteIPStr)

	if err != nil {
		tcpErr = NewTCPError(102, "Remote IP format error\n%v", err)
		return localAddrBytes, remoteAddrBytes, tcpErr
	}
	return localAddrBytes, remoteAddrBytes, tcpErr
}

func checksum(data []byte) uint16 {
	sum := uint32(0)

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for (sum >> 16) > 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return uint16(^sum)
}

func validateFlags(reg uint8, flags uint8) bool {
	if (reg & flags) != flags {
		return false
	}
	return true
}

func (conn *TCPConn) generateInitSeqNum() uint32 {
	var ipSum uint32
	ipSum = 0
	for i := 0; i < 4; i++ {
		ipSum += uint32(conn.LocalAddr.Addr[i]) + uint32(conn.RemoteAddr.Addr[i])
	}
	ipSum += uint32(conn.LocalAddr.Port) + uint32(conn.LocalAddr.Port)
	return uint32(rand.Int31n(int32(ipSum)) + int32(time.Now().UnixMicro()%4))
}

func (conn *TCPConn) getUsableWin() uint16 {
	return uint16(uint32(conn.RecvVars.Window) - (conn.SendVars.Next - conn.SendVars.UnAck))
}

func serializeTCPPack(packet TCPPack) []byte {
	buff := make([]byte, 20+(len(packet.Data)))

	binary.BigEndian.PutUint16(buff[0:2], packet.Src)
	binary.BigEndian.PutUint16(buff[2:4], packet.Dst)
	binary.BigEndian.PutUint32(buff[4:8], packet.SeqNum)
	binary.BigEndian.PutUint32(buff[8:12], packet.AckNum)

	offsetAndFlags := uint16(uint16(packet.Flags) | uint16(packet.Offset)<<12)

	binary.BigEndian.PutUint16(buff[12:14], offsetAndFlags)
	binary.BigEndian.PutUint16(buff[14:16], packet.Window)
	binary.BigEndian.PutUint16(buff[16:18], packet.Checksum)
	binary.BigEndian.PutUint16(buff[18:20], packet.UrgentPtr)

	// present only when DOffset > 5
	if packet.Offset > 5 {
		for i, option := range packet.Options {
			buff[i] = option.Kind
			if option.Length > 1 {
				buff[i] = option.Length
				for j, data := range option.Data {
					buff[j] = data
				}
			}
		}
	}

	if len(packet.Data) > 0 {
		fmt.Println("Received data to send")
		//conn.log(DEBUG, nil, "Received data to send")
		copy(buff[20:], packet.Data)
	}
	return buff
}

func deserializeTCPPack(buff []byte) TCPPack {
	var packet TCPPack

	packet.Src = binary.BigEndian.Uint16(buff[0:2])
	packet.Dst = binary.BigEndian.Uint16(buff[2:4])
	packet.SeqNum = binary.BigEndian.Uint32(buff[4:8])
	packet.AckNum = binary.BigEndian.Uint32(buff[8:12])

	offsetAndFlags := binary.BigEndian.Uint16(buff[12:14])

	packet.Offset = uint8(offsetAndFlags >> 12)
	packet.Flags = uint8(offsetAndFlags & 0xFF)
	packet.Window = binary.BigEndian.Uint16(buff[14:16])

	// TODO: verify Checksum
	packet.Checksum = binary.BigEndian.Uint16(buff[16:18])
	packet.UrgentPtr = binary.BigEndian.Uint16(buff[18:20])

	// Parse options if data offset > 5
	if packet.Offset > 5 {
		optionsLength := (int(packet.Offset-5) << 2)
		optionsData := buff[20 : 20+optionsLength]
		// for i := 0; i < optionsLength; {
		kind := optionsData[0]
		if kind == 2 { // End of options list
			length := optionsData[1]
			option := TCPOption{
				Kind:   kind,
				Length: length,
				Data:   optionsData[2:4],
			}
			packet.Options = append(packet.Options, option)
		}
	}

	// TODO: Fix length
	packet.Length = 0
	return packet
}

func serializePseudoIPHdr(srcIP [4]byte, dstIP [4]byte, ptcl uint8, length uint16) []byte {
	buff := make([]byte, 12)

	copy(buff[0:4], srcIP[:])
	copy(buff[4:8], dstIP[:])
	buff[9] = ptcl
	binary.BigEndian.PutUint16(buff[10:12], length)

	return buff
}

// process ack
// recv : ack after send or recv
func (conn *TCPConn) validateAndUpdateVars(recv bool, seg SegVars) bool {
	if !recv {
		if seg.AckNum <= conn.SendVars.Next {
			if validateFlags(seg.Flags, SYN) || validateFlags(seg.Flags, FIN) || validateFlags(seg.Flags, PSH) {
				conn.SendVars.LastAckNum = seg.SeqNum + uint32(seg.Length) + 1
			} else {
				conn.SendVars.LastAckNum = seg.SeqNum + uint32(seg.Length)
			}
			// for now ; not sure about this though
			if conn.SendVars.UnAck < seg.AckNum {
				conn.log(DEBUG, nil, "Updating ->UnACK: %v AckNum: %v Next: %v, Flags: %v", conn.SendVars.UnAck, seg.AckNum, conn.SendVars.Next, seg.Flags)
				conn.SendVars.UnAck = seg.AckNum
				conn.RecvVars.Window = seg.Window
				ok := conn.SendPacketQueue.Dequeue(seg.AckNum)
				if !ok {
					conn.log(ERROR, nil, "Dequeue failed ackNum : %v", seg.AckNum)
				}
				return true
			}
			// if conn.SendVars.UnAck == seg.AckNum { //&& (conn.ReTransSeqNum != seg.AckNum) {
			// 	conn.log(ERROR, nil, "Received a duplicate ack resending the packet :ackNum:%v", seg.AckNum)
			// 	//conn.FastReTransCh <- seg.AckNum
			// 	conn.ReTransSeqNum = seg.AckNum
			// }
		} else {
			conn.log(DEBUG, nil, "AckNum: %v is not less than Next %v", seg.AckNum, conn.SendVars.Next)
		}
	}
	return false
}

func (conn *TCPConn) sendFlags(flags uint8) error {
	var packet TCPPack

	packet.Src = conn.LocalPort
	packet.Dst = conn.RemotePort
	if flags == SYN {
		packet.SeqNum = conn.generateInitSeqNum()
		conn.SendVars.UnAck = packet.SeqNum
	} else {
		conn.log(DEBUG, nil, "FIN Seq %v", conn.SendVars.Next)
		packet.SeqNum = conn.SendVars.Next
	}
	packet.AckNum = conn.SendVars.LastAckNum
	packet.Offset = 5
	packet.Flags = flags
	packet.Window = 65535
	packet.Checksum = 0
	packet.UrgentPtr = 0
	packet.Length = 0

	err := conn.sendSeg(packet)
	if err != nil {
		fmt.Println("Error sending ack", err)
	}
	return err
}

func (conn *TCPConn) sendSeg(packet TCPPack) error {

	serTCPPack := serializeTCPPack(packet)
	serPseudoHdr := serializePseudoIPHdr(conn.LocalAddr.Addr, conn.RemoteAddr.Addr, syscall.IPPROTO_TCP, uint16(len(serTCPPack)))

	// update checksum
	binary.BigEndian.PutUint16(serTCPPack[16:18], checksum(append(serPseudoHdr, serTCPPack...)))

	err := conn.sendRaw(serTCPPack)
	if err != nil {
		conn.log(ERROR, &packet, "Error sending packet:", err)
		//fmt.Println("Error sending packet:", err)
	} else {
		conn.log(DEBUG, &packet, "Sent packet")
		if (validateFlags(packet.Flags, SYN)) || (validateFlags(packet.Flags, FIN)) {
			conn.SendVars.Next = packet.SeqNum + uint32((packet.Offset-5)<<2) + 1 // (packet.Offset - 5) + 1
		} else if !validateFlags(packet.Flags, PSH) {
			conn.SendVars.Next = packet.SeqNum
		} else if validateFlags(packet.Flags, PSH) {
			conn.SendVars.Next = packet.SeqNum + uint32((packet.Offset-5)<<2) + uint32(packet.Length)
		}
	}
	return err
}

func (conn *TCPConn) sendRaw(data []byte) error {
	err := syscall.Sendto(conn.Fd, data, 0, &conn.RemoteAddr)
	if err != nil {
		fmt.Println("Error sending packet:", err)
	}
	return err
}

func (conn *TCPConn) recvFlags(flags uint8) error {
	var err, tcpErr error
	var seg SegVars

	seg, err = conn.recvSeg(1024)

	if err != nil {
		tcpErr = NewTCPError(104, "Error receiving SYN packet\n%v", err)
		return tcpErr
	}

	if validateFlags(seg.Flags, flags) {
		ret := conn.validateAndUpdateVars(false, seg)
		if !ret {
			tcpErr = NewTCPError(105, "Error validating SYN ACK packet\n%v", err)
			return tcpErr
		}
	} else {
		tcpErr = NewTCPError(106, "Error validating flags SYN ACK packet\n%v", err)
		return tcpErr
	}
	return tcpErr
}

func (conn *TCPConn) recvFinAck() error {
	var err, tcpErr error
	var seg SegVars
	for {
		seg, err = conn.recvSeg(1024)

		if err != nil {
			tcpErr = NewTCPError(107, "Error receiving SYN packet\n%v", err)
			return tcpErr
		}

		if validateFlags(seg.Flags, ACK) || validateFlags(seg.Flags, FIN|ACK) {
			ret := conn.validateAndUpdateVars(false, seg)
			if !ret {
				conn.log(DEBUG, nil, "UnACK: %v AckNum: %v Next: %v", conn.SendVars.UnAck, seg.AckNum, conn.SendVars.Next)
				//return tcpErr
			}
			if validateFlags(seg.Flags, FIN) {
				break
			}

		} else {
			tcpErr = NewTCPError(109, "Error validating flags SYN ACK packet\n%v", err)
			return tcpErr
		}
	}
	return tcpErr
}

// currently only supports ACK and RST
func (conn *TCPConn) recvAny() (bool, error) {
	var err, tcpErr error
	var seg SegVars
	isReset := false
	seg, err = conn.recvSegNonBloc(1024)

	if err != nil {
		if tcpErr, ok := err.(*TCPError); ok {
			if tcpErr.Code == 300 {
				return isReset, tcpErr
			}
		}
		tcpErr = NewTCPError(110, "Error receiving SYN packet\n%v", err)
		return isReset, tcpErr
	}

	if validateFlags(seg.Flags, ACK) || validateFlags(seg.Flags, RST) {
		ret := conn.validateAndUpdateVars(false, seg)
		if !ret {
			tcpErr = NewTCPError(111, "Error validating SYN ACK packet\n%v", err)
			//return isReset, tcpErr
		}
		if validateFlags(seg.Flags, RST) {
			isReset = true
		}
	} else {
		tcpErr = NewTCPError(112, "Error validating flags SYN ACK packet\n%v", err)
		return isReset, tcpErr
	}
	return isReset, tcpErr
}

func (conn *TCPConn) recvSeg(size int) (SegVars, error) {
	var err, tcpErr error
	var seg SegVars
	buff := make([]byte, size)
	recvLen := int(0)

	for {
		buff, recvLen, err = conn.recvRaw(1024)
		if err != nil {
			if tcpErr, ok := err.(*TCPError); ok {
				if tcpErr.Code == 300 {
					continue
				}
			}
			tcpErr = NewTCPError(350, "Error receiving segment\n%v", err)
			break
		}

		if recvLen > 0 {
			tcpErr = nil
			deserPack := deserializeTCPPack(buff)
			// filter
			if (deserPack.Dst == conn.LocalPort) && (deserPack.Src == conn.RemotePort) {
				conn.log(DEBUG, &deserPack, "Received packet length:%v", recvLen)
				if validateFlags(deserPack.Flags, SYN) {
					for _, option := range deserPack.Options {
						if option.Kind == 2 {
							conn.RecvVars.MSS = binary.BigEndian.Uint16(option.Data[0:2])
							conn.EffSNDMSS = conn.RecvVars.MSS - IPV4HDRLEN - TCPHDRLEN // TODO: TCPHDRLEN might change
							conn.log(DEBUG, &deserPack, "Setting MSS: %v", conn.RecvVars.MSS)
						}
					}
				}

				seg = SegVars{
					SeqNum:    deserPack.SeqNum,
					AckNum:    deserPack.AckNum,
					Length:    uint16(recvLen) - uint16((deserPack.Offset << 2)), // TODO: fix this
					Window:    deserPack.Window,
					Flags:     deserPack.Flags,
					UrgentPtr: deserPack.UrgentPtr,
				}
				return seg, tcpErr
			}
		} else {
			tcpErr = NewTCPError(352, "Received empty buffer")
			//break
		}
	}
	return seg, tcpErr
}

func (conn *TCPConn) recvSegNonBloc(size int) (SegVars, error) {
	var err, tcpErr error
	var seg SegVars
	buff := make([]byte, size)
	recvLen := int(0)

	buff, recvLen, err = conn.recvRaw(1024)
	if err != nil {
		if tcpErr, ok := err.(*TCPError); ok {
			if tcpErr.Code == 300 {
				return seg, tcpErr
			}
		}
		tcpErr = NewTCPError(350, "Error receiving segment\n%v", err)
		return seg, tcpErr
	}

	if recvLen > 0 {
		deserPack := deserializeTCPPack(buff)
		// filter
		if (deserPack.Dst == conn.LocalPort) && (deserPack.Src == conn.RemotePort) {
			conn.log(DEBUG, &deserPack, "Received packet length:%v", recvLen)
			if validateFlags(deserPack.Flags, SYN) {
				for _, option := range deserPack.Options {
					if option.Kind == 2 {
						conn.RecvVars.MSS = binary.BigEndian.Uint16(option.Data[0:2])
						conn.log(DEBUG, &deserPack, "Setting MSS: %v", conn.RecvVars.MSS)
					}
				}
			}

			seg = SegVars{
				SeqNum:    deserPack.SeqNum,
				AckNum:    deserPack.AckNum,
				Length:    uint16(recvLen) - uint16((deserPack.Offset << 2)), // TODO: fix this
				Window:    deserPack.Window,
				Flags:     deserPack.Flags,
				UrgentPtr: deserPack.UrgentPtr,
			}
			return seg, tcpErr
		}
	} else {
		tcpErr = NewTCPError(352, "Received empty buffer")
	}
	return seg, tcpErr
}

func (conn *TCPConn) recvRaw(size int) ([]byte, int, error) {
	buff := make([]byte, size)
	var err error
	var tcpErr error
	var recvLen int
	var sockAddr syscall.Sockaddr

	recvLen, sockAddr, err = syscall.Recvfrom(conn.Fd, buff, 0)
	sockAddrInet4, _ := sockAddr.(*syscall.SockaddrInet4)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EINTR {
			// Non-blocking timeout reached, loop again
			tcpErr = NewTCPError(300, "Recv Timout\n%v", err)
		} else {
			tcpErr = NewTCPError(301, "Error in recv packet\n%v", err)
		}
		return buff, 0, tcpErr
	}
	if bytes.Equal(sockAddrInet4.Addr[:], conn.RemoteAddr.Addr[:]) {
		// remove IP header
		return buff[IPV4HDRLEN:], (recvLen - IPV4HDRLEN), tcpErr
	}

	return buff, 0, tcpErr
}

// func (conn *TCPConn) Abort() {
// }

// func (conn *TCPConn) Status() {
// }

func (conn *TCPConn) Send(data []byte, size uint16) error {
	var tcpErr error

	if (size < conn.EffSNDMSS) && (size < conn.getUsableWin()) {
		var packet TCPPack

		packet.Length = size
		packet.Data = make([]byte, size)
		copy(packet.Data[:size], data[:size])
		conn.SendPackCh <- packet
		conn.log(DEBUG, nil, "Next is updated:%v", conn.SendVars.Next)

	} else {
		tcpErr = NewTCPError(401, "Size of data to be send is greater than EffSNDMSS or usable Window")
	}
	return tcpErr
}

func (conn *TCPConn) Open(localIPStr string, localPort uint16, remoteIPStr string, remotePort uint16) error {
	var err, tcpErr error

	var localAddrBytes, remoteAddrBytes [4]byte

	err = conn.stateChange(IDLE)

	localAddrBytes, remoteAddrBytes, err = validateAddrFormat(localIPStr, remoteIPStr)

	if err != nil {
		tcpErr = NewTCPError(103, "Address validation failed\n%v", err)
		return tcpErr
	}

	localAddrInt := syscall.SockaddrInet4{
		Addr: localAddrBytes,
		Port: int(localPort),
	}

	remoteAddrInt := syscall.SockaddrInet4{
		Addr: remoteAddrBytes,
		Port: int(remotePort),
	}

	conn.LocalAddr = localAddrInt
	conn.RemoteAddr = remoteAddrInt
	conn.LocalPort = localPort
	conn.RemotePort = remotePort

	// init CONNECT request
	err = conn.stateChange(CONNECT)
	if err != nil {
		tcpErr = NewTCPError(104, "Error changing state for CONNECT\n%v", err)
		return tcpErr
	}

	return tcpErr
}

func (conn *TCPConn) Close() error {
	var err, tcpErr error
	err = conn.stateChange(CLOSE)
	if err != nil {
		tcpErr = NewTCPError(900, "Failed in closing the connection\n%v", err)
	}
	return tcpErr
}

// for now it only applies for recv acks
// this is a single instance of recv
// not other function should exec recv without
// closing this loop
func (conn *TCPConn) listen() {
	var err error
	var isReset bool

	for {
		select {
		case <-conn.CloseListenCh:
			//conn.log(DEBUG, nil, "Exiting listen loop")
			return
		case seqNum := <-conn.FastReTransCh:

			conn.SendPacketQueue.mu.RLock()
			defer conn.SendPacketQueue.mu.RUnlock()

			var keys []uint32
			for key := range conn.SendPacketQueue.items {
				if key >= seqNum {
					keys = append(keys, key)
				}
			}

			// Sort the keys in ascending order to ensure packets are sent in order
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

			// Iterate over sorted keys and send each packet in the correct order

			count := 0
			maxPackets := 5 // Number of packets to process

			for _, key := range keys {
				if count >= maxPackets {
					break // Exit the loop after processing three packets
				}

				ok, packet := conn.SendPacketQueue.Get(key)
				if ok {
					err := conn.sendSeg(packet)
					if err != nil {
						conn.log(ERROR, &packet, "Sending data failed\n%v", err)
					} else {
						conn.SendPackCount++
					}
				} else {
					conn.log(ERROR, nil, "You are trying to send a packet which doesn't exist in the queue", err)
				}

				// Increment the counter after processing a packet
				count++
			}
			// for _, key := range keys {
			// 	ok, packet := conn.SendPacketQueue.Get(key)
			// 	if ok {
			// 		err = conn.sendSeg(packet)
			// 		if err != nil {
			// 			conn.log(ERROR, &packet, "Sending data failed\n%v", err)
			// 		} else {
			// 			conn.SendPackCount++
			// 		}
			// 	} else {
			// 		conn.log(ERROR, nil, "You are trying to send a packet which doesn't exist in the queue", err)
			// 	}
			// }

			// ok, packet := conn.SendPacketQueue.Get(seqNum)
			// if ok {
			// 	err = conn.sendSeg(packet)
			// 	if err != nil {
			// 		conn.log(ERROR, &packet, "Sending data failed\n%v", err)
			// 	} else {
			// 		conn.SendPackCount++
			// 	}
			// } else {
			// 	conn.log(ERROR, nil, "You are trying to send an packet which doesn't exist in the queue", err)
			// }
		case packet := <-conn.SendPackCh:

			packet.SeqNum = conn.SendVars.Next
			packet.Src = conn.LocalPort
			packet.Dst = conn.RemotePort
			packet.AckNum = conn.SendVars.LastAckNum
			packet.Offset = 5
			packet.Flags = PSH | ACK
			packet.Window = 65535
			packet.Checksum = 0
			packet.UrgentPtr = 0
			err = conn.sendSeg(packet)
			if err != nil {
				conn.log(ERROR, &packet, "Sending data failed\n%v", err)
			} else {
				conn.log(DEBUG, nil, "Channel: Updating Next, %v", conn.SendVars.Next)
				conn.SendPacketQueue.Enqueue(packet)
				conn.SendPackCount++
				recvTO := time.NewTicker(1 * time.Second)
				maxReTrans := 10
				reTransCount := 0
			breakRecvLoop:
				for {
					select {
					case <-recvTO.C:
						if reTransCount < maxReTrans {
							conn.log(ERROR, nil, "Retransmitting%v\n", packet.SeqNum)
							err = conn.sendSeg(packet)
							if err != nil {
								conn.log(ERROR, &packet, "Sending data failed\n%v", err)
							} else {
								reTransCount++
							}
						} else {
							recvTO.Stop()
							break breakRecvLoop
						}
					default:
						isReset, err = conn.recvAny()
						if err != nil {
							//if tcpErr, ok := err.(*TCPError); ok {
							//if tcpErr.Code == 300 {
							//conn.log(ERROR, nil, "Error receiving segment\n%v", err)
							continue
							//}
							//}

							//break breakRecvLoop
						}

						if isReset {
							conn.log(DEBUG, nil, "Reset received from remote connection")
							return
						}
						recvTO.Stop()
						//conn.log(DEBUG, nil, "received ACK, not breaking recvLOOP")
						break breakRecvLoop
					}
				}
			}

			// default:
			// 	isReset, err = conn.recvAny()
			// 	if err != nil {
			// 		//if tcpErr, ok := err.(*TCPError); ok {
			// 		//if tcpErr.Code == 300 {
			// 		//conn.log(ERROR, nil, "Error receiving segment\n%v", err)
			// 		continue
			// 		//}
			// 		//}
			// 	}

			// 	if isReset {
			// 		conn.log(DEBUG, nil, "Reset received from remote connection")
			// 		return
			// 	}
		}
	}
}

func (conn *TCPConn) stateChange(state uint8) error {
	var err, tcpErr error

	switch state {
	case IDLE:
		// do more like check current state and stuff
		conn.State = IDLE
	case CONNECT:
		if conn.State == IDLE {
			var fd int

			fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)

			if err != nil {
				tcpErr = NewTCPError(0, "Failed to create socket\n%v", err)
				return tcpErr
			}

			err = syscall.Bind(fd, &conn.LocalAddr)
			if err != nil {
				tcpErr = NewTCPError(1, "Error binding local address to socket\n%v", err)
				return tcpErr
			}

			conn.Fd = fd
			conn.RecvVars.MSS = 536
			conn.CloseListenCh = make(chan bool)
			conn.SendPackCh = make(chan TCPPack)
			conn.FastReTransCh = make(chan uint32, 1000)
			conn.SendPacketQueue = NewQueue()
			conn.SendPackCount = 0
			conn.ReTransSeqNum = 0
			// setting recv timeout
			tv := syscall.NsecToTimeval(1) // 0.1ms
			syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

			// init handshake
			err = conn.sendFlags(SYN)
			if err != nil {
				tcpErr = NewTCPError(2, "Failed to send SYN\n%v", err)
				return tcpErr
			}
			conn.State = SYNSENT

			err = conn.recvFlags(SYN | ACK)
			if err != nil {
				tcpErr = NewTCPError(3, "Failed to recv SYN\n%v", err)
				return tcpErr
			}
			conn.State = SYNRECV

			err = conn.sendFlags(ACK)
			if err != nil {
				tcpErr = NewTCPError(4, "Failed to send ACK after recv SYN\n%v", err)
				return tcpErr
			}
			// default for IPv4
			conn.EffSNDMSS = conn.RecvVars.MSS - IPV4HDRLEN - TCPHDRLEN // TODO: TCPHDRLEN might change
			conn.State = ESTABLISHED
			conn.log(DEBUG, nil, "Connection is established")

			go conn.listen()

		} else {
			tcpErr = NewTCPError(5, "Can't change state to CONNECT, current state is not IDLE")
		}
	case CLOSE:
		if conn.State == ESTABLISHED {
			conn.log(DEBUG, nil, "Sent Connection close req")
			conn.CloseListenCh <- true
			conn.State = FINWAIT1

			err = conn.sendFlags(FIN | ACK)
			if err != nil {
				tcpErr = NewTCPError(6, "Failed to send FIN\n%v", err)
				return tcpErr
			}
			conn.State = FINWAIT2

			err = conn.recvFinAck()
			if err != nil {
				tcpErr = NewTCPError(7, "Failed to recv FIN ACK\n%v", err)
				return tcpErr
			}
			conn.State = TIMEWAIT

			err = conn.sendFlags(ACK)
			if err != nil {
				tcpErr = NewTCPError(8, "Failed to send ACK after FIN ACK\n%v", err)
				return tcpErr
			}

			err = syscall.Close(conn.Fd)
			if err != nil {
				tcpErr = NewTCPError(9, "Failed to close connection\n%v", err)
				return tcpErr
			}
			conn.State = CLOSED
			conn.log(DEBUG, nil, "Connection closed")

		} else {
			tcpErr = NewTCPError(10, "Connection is not EST. before closing")
		}
	}
	return tcpErr
}

func main() {

	var conn TCPConn
	var localIP, remoteIP string
	var localPort, remotePort int

	args := os.Args

	if len(args) != 5 {
		fmt.Println("Usage: program [LOCAL_IP] [LOCAL_PORT] [REMOTE_IP] [REMOTE_PORT]")
		return
	}

	localIP = args[1]
	remoteIP = args[3]
	localPort, _ = strconv.Atoi(args[2])
	remotePort, _ = strconv.Atoi(args[4])

	err := conn.Open(localIP, uint16(localPort), remoteIP, uint16(remotePort))
	var tcpErr error
	if err != nil {
		tcpErr = NewTCPError(0, "Error opening connection\n%v", err)
		fmt.Println(tcpErr)
		return
	}

	byteArray := make([]byte, 1024)
	for i := range byteArray {
		byteArray[i] = 0xff
	}

	// for i := 0; i < 500; i++ {
	// 	// Check if the queue length is greater than 10
	// 	for conn.SendPacketQueue.Len() > 5 {
	// 		// Wait before checking again
	// 		time.Sleep(time.Millisecond * 100) // Adjust the sleep duration as needed
	// 		continue
	// 	}

	// 	// Attempt to send data
	// 	err := conn.Send(byteArray, uint16(len(byteArray)))
	// 	if err != nil {
	// 		tcpErr := NewTCPError(1, "Error sending data\n%v", err)
	// 		fmt.Println(tcpErr)
	// 		break
	// 	}
	// }
	for i := 0; i < 10000; i++ {
		err = conn.Send(byteArray, uint16(len(byteArray)))
		if err != nil {
			tcpErr = NewTCPError(1, "Error closing connection\n%v", err)
			fmt.Println(tcpErr)
			break
		}
		//time.Sleep(100 * time.Millisecond)
	}

	conn.Close()

	// ticker := time.NewTicker(5 * time.Second)
	// defer ticker.Stop()

	// for range ticker.C {
	// 	if conn.SendPacketQueue.Len() <= 1 {
	// 		err = conn.Close()
	// 		if err != nil {
	// 			tcpErr = NewTCPError(2, "Error closing connection\n%v", err)
	// 			fmt.Println(tcpErr)
	// 		}
	// 		break
	// 	} else {
	// 		fmt.Println("Queue length :", conn.SendPacketQueue.Len())
	// 	}
	// }
}
