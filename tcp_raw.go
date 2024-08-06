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

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"
)

const (
	LISTEN    = 1
	SYNSENT   = 2
	SYNRECV   = 3
	ESTB      = 4
	FINWAIT1  = 5
	FINWAIT2  = 6
	CLOSEWAIT = 7
	CLOSING   = 8
	LASTACK   = 9
	TIMEWAIT  = 10
	CLOSED    = 11
)

const (
	IPV4HDRLEN = 20
)

const (
	FIN = 1
	SYN = 2
	RST = 4
	PSH = 8
	ACK = 16
	URG = 32
	ECE = 64
	CWR = 128
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

type TCPHdr struct {
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
	Fd         int
	LocalAddr  syscall.SockaddrInet4
	RemoteAddr syscall.SockaddrInet4
	LocalPort  uint16
	RemotePort uint16
	Hdr        TCPHdr
	SendVars   SendVars
	RecvVars   RecvVars
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

func log(level int, packet TCPHdr, format string, a ...interface{}) {

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
		// [PORT -> PORT] [FLAGS] [Seq, Ack, Win, Len] [Status]
		debugString := fmt.Sprintf("%s[%v] %sCONN[%v -> %v] %sFLAGS[%-8v] %s[Seq=%-10v, Ack=%-10v, Win=%-6v, Len=%-4v] .......... %s",
			msgColor, time.Now().UnixMilli(),
			IYELBG, packet.Src, packet.Dst,
			IGRNBG, flagsIntToStr(packet.Flags),
			KWHT, packet.SeqNum, packet.AckNum, packet.Window, packet.Length, msgColor)
		debugString2 := fmt.Sprintf(format+"\n", a...)
		debug := logLevelString + debugString + debugString2
		_, _ = fmt.Printf(debug)
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

func checksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	return uint16(^sum)
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

func serializeTCPPack(packet TCPHdr) []byte {
	buff := make([]byte, 20)

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

	return buff
}

func deserializeTCPPack(buff []byte) TCPHdr {
	var packet TCPHdr

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
		for i := 0; i < optionsLength; {
			kind := optionsData[i]
			if kind == 0 { // End of options list
				break
			}
			length := optionsData[i+1]
			option := TCPOption{
				Kind:   kind,
				Length: length,
				Data:   optionsData[i+2 : i+int(length)],
			}
			packet.Options = append(packet.Options, option)
			i += int(length)
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

func (conn *TCPConn) initHandShake() error {
	var err error
	var packet TCPHdr

	packet.Src = conn.LocalPort
	packet.Dst = conn.RemotePort
	packet.SeqNum = conn.generateInitSeqNum()
	packet.AckNum = 0
	packet.Offset = 5
	packet.Flags = SYN
	packet.Window = 128
	packet.Checksum = 0
	packet.UrgentPtr = 0
	packet.Length = 0

	conn.SendVars.UnAck = packet.SeqNum
	conn.SendVars.InitSeqNum = packet.SeqNum

	err = conn.sendSeg(packet)
	if err != nil {
		fmt.Println("Error sending packet:", err)
		return err
	}

	var seg SegVars
	seg, err = conn.recvSeg(1024)

	if err != nil {
		fmt.Println("Error receiving packet:", err)
		return err
	}

	if validateFlags(seg.Flags, SYN|ACK) {
		// send ack
		ret := conn.validateAndUpdateVars(false, seg)
		if ret {
			// send ACK
			err = conn.sendAck()
		}
	}
	return err
}

func (conn *TCPConn) sendAck() error {
	var packet TCPHdr

	packet.Src = conn.LocalPort
	packet.Dst = conn.RemotePort
	packet.SeqNum = conn.SendVars.Next
	packet.AckNum = conn.SendVars.LastAckNum
	packet.Offset = 5
	packet.Flags = ACK
	packet.Window = 128
	packet.Checksum = 0
	packet.UrgentPtr = 0
	packet.Length = 0

	err := conn.sendSeg(packet)
	if err != nil {
		fmt.Println("Error sending ack", err)
	}
	return err
}

func (conn *TCPConn) sendFin() error {
	var packet TCPHdr

	packet.Src = conn.LocalPort
	packet.Dst = conn.RemotePort
	packet.SeqNum = conn.SendVars.Next
	packet.AckNum = conn.SendVars.LastAckNum
	packet.Offset = 5
	packet.Flags = FIN | ACK
	packet.Window = 128
	packet.Checksum = 0
	packet.UrgentPtr = 0

	err := conn.sendSeg(packet)
	if err != nil {
		fmt.Println("Error sending FIN", err)
	}
	return err
}

func (conn *TCPConn) Open(localIPStr string, localPort uint16, remoteIPStr string, remotePort uint16) error {

	var fd int
	var err error

	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)

	if err != nil {
		fmt.Println("Error creating socket:", err)
		return err
	}

	localAddrBytes, err := IPStrtoBytes(localIPStr)

	if err != nil {
		tcpErr = NewTCPError(101, "Local IP format error\n%v", err)
		return tcpErr
	}

	remoteAddrBytes, err := IPStrtoBytes(remoteIPStr)

	if err != nil {
		tcpErr = NewTCPError(102, "Remote IP format error\n%v", err)
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

	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)

	if err != nil {
		tcpErr = NewTCPError(103, "Failed to create socket\n%v", err)
		return tcpErr
	}

	err = syscall.Bind(fd, &localAddrInt)
	if err != nil {
		tcpErr = NewTCPError(103, "Error binding local address to socket\n%v", err)
		return tcpErr
	}

	conn.Fd = fd
	conn.LocalAddr = localAddrInt
	conn.RemoteAddr = remoteAddrInt
	conn.LocalPort = localPort
	conn.RemotePort = remotePort

	// TODO: call threeway handshare
	err = conn.initHandShake()

	if err != nil {
		tcpErr = NewTCPError(103, "TCP Handshake Failed\n%v", err)
		return tcpErr
	}

	return tcpErr
}

func (conn *TCPConn) Close() error {
	err := conn.sendFin()
	var tcpErr error
	if err != nil {
		tcpErr = NewTCPError(900, "Failed to send FIN\n%v", err)
		return tcpErr
	}

	var seg SegVars
	seg, err = conn.recvSeg(1024) // FINACK ; TODO: Server might send ACK and then FINACK

	if validateFlags(seg.Flags, FIN|ACK) {
		// send ack
		ret := conn.validateAndUpdateVars(false, seg)
		if ret {
			// send ACK
			err = conn.sendAck()
			if err != nil {
				tcpErr = NewTCPError(901, "Failed to send ACK after receiving FINACK while closing\n%v", err)
				return tcpErr
			}

		}
	} else {
		tcpErr = NewTCPError(902, "Failed to recv FINACK after sending FIN\n%v", err)
		return tcpErr
	}

	err = syscall.Close(conn.Fd)
	if err != nil {
		tcpErr = NewTCPError(903, "Failed to close connection\n%v", err)
		return tcpErr
	}
	return tcpErr
}

func (conn *TCPConn) sendSeg(packet TCPHdr) error {

	serTCPPack := serializeTCPPack(packet)
	serPseudoHdr := serializePseudoIPHdr(conn.LocalAddr.Addr, conn.RemoteAddr.Addr, syscall.IPPROTO_TCP, uint16(len(serTCPPack)))

	// update checksum
	binary.BigEndian.PutUint16(serTCPPack[16:18], checksum(append(serPseudoHdr, serTCPPack...)))

	err := conn.sendRaw(serTCPPack)
	if err != nil {
		log(ERROR, packet, "Error sending packet:", err)
		//fmt.Println("Error sending packet:", err)
	} else {
		log(DEBUG, packet, "Sent packet")
		if (validateFlags(packet.Flags, SYN)) || (validateFlags(packet.Flags, FIN)) || (validateFlags(packet.Flags, PSH)) {
			conn.SendVars.Next = packet.SeqNum + uint32((packet.Offset-5)<<2) + 1 // (packet.Offset - 5) + 1
		} else {
			conn.SendVars.Next = packet.SeqNum
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

func (conn *TCPConn) recvSeg(size int) (SegVars, error) {
	var err error
	var tcpErr error
	var seg SegVars
	buff := make([]byte, size)
	recvLen := int(0)
	buff, recvLen, err = conn.recvRaw(1024)
	if err != nil {
		tcpErr = NewTCPError(350, "Error receiving segment\n%v", err)
		return seg, tcpErr
	}
	if recvLen > 0 {
		deserPack := deserializeTCPPack(buff)
		log(DEBUG, deserPack, "Received packet")
		if (deserPack.Dst == conn.LocalPort) && (deserPack.Src == conn.RemotePort) {
			if validateFlags(deserPack.Flags, SYN) {
				for _, option := range deserPack.Options {
					if option.Kind == 2 {
						conn.RecvVars.MSS = binary.BigEndian.Uint16(option.Data[0:2])
						log(DEBUG, deserPack, "Setting MSS: %v", conn.RecvVars.MSS)
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
		} else {
			tcpErr = NewTCPError(351, "Ports doesn't match")
		}
	} else {
		tcpErr = NewTCPError(352, "Received empty buffer")
	}

	return seg, tcpErr
}

// process ack
// recv : ack after send or recv
func (conn *TCPConn) validateAndUpdateVars(recv bool, seg SegVars) bool {
	if !recv {
		if (conn.SendVars.UnAck < seg.AckNum) && (seg.AckNum <= conn.SendVars.Next) {
			if validateFlags(seg.Flags, SYN) || validateFlags(seg.Flags, FIN) {
				conn.SendVars.LastAckNum = seg.SeqNum + uint32(seg.Length) + 1
			} else {
				conn.SendVars.LastAckNum = seg.SeqNum + uint32(seg.Length)
			}
			// for now ; not sure about this though
			conn.SendVars.UnAck = seg.AckNum
			return true
		}
	}
	return false
}

func validateFlags(reg uint8, flags uint8) bool {
	if (reg & flags) != flags {
		return false
	}
	return true
}

func (conn *TCPConn) recvRaw(size int) ([]byte, int, error) {
	buff := make([]byte, size)
	var err error
	var tcpErr error
	var recvLen int
	var sockAddr syscall.Sockaddr
	for {
		recvLen, sockAddr, err = syscall.Recvfrom(conn.Fd, buff, 0)
		sockAddrInet4, _ := sockAddr.(*syscall.SockaddrInet4)
		if err != nil {
			tcpErr = NewTCPError(300, "Error in recv packet\n%v", err)
			break
		}
		if bytes.Equal(sockAddrInet4.Addr[:], conn.RemoteAddr.Addr[:]) {
			// remove IP header
			return buff[IPV4HDRLEN:], (recvLen - IPV4HDRLEN), tcpErr
		} else {
			continue
		}
	}
	return buff, 0, tcpErr
}

// func (conn *TCPConn) Abort() {
// }

// func (conn *TCPConn) Status() {
// }

func main() {

	var conn TCPConn
	err := conn.Open("10.68.186.2", 8080, "10.72.138.186", 50000)
	var tcpErr error
	if err != nil {
		tcpErr = NewTCPError(0, "Error opening connection\n%v", err)
		fmt.Println(tcpErr)
		return
	}
	err = conn.Close()
	if err != nil {
		tcpErr = NewTCPError(1, "Error closing connection\n%v", err)
		fmt.Println(tcpErr)
	}
}
