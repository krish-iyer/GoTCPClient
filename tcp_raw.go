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
	"net"
	// "strconv"
	"errors"
	"math/rand"
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
	FIN = 1
	SYN = 2
	RST = 4
	PSH = 8
	ACK = 16
	URG = 32
	ECE = 64
	CWR = 128
)

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
}

type SegVars struct {
	SeqNum    uint32
	AckNum    uint32
	Length    uint32
	Window    uint16
	UrgentPtr uint16
}

type TCPConn struct {
	Fd         int
	LocalAddr  syscall.SockaddrInet4
	RemoteAddr syscall.SockaddrInet4
	Hdr        TCPHdr
}

func IPStrtoBytes(ip string) ([4]byte, error) {
	var err error
	ipBytes := net.ParseIP(ip).To4()
	var resizeIP [4]byte

	if ipBytes != nil {
		copy(resizeIP[:], ipBytes)
		err = nil
	} else {
		err = errors.New("Invalid IPv4 Address")
	}

	return resizeIP, err
}

func Checksum(data []byte) uint16 {
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
	//rand.Seed((time.Now().UnixMicro() % 4))
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
		optionsLength := (int(packet.Offset) * 4) - 20
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
	var packetHdr TCPHdr

	packetHdr.Src = conn.Hdr.Src
	packetHdr.Dst = conn.Hdr.Dst
	packetHdr.SeqNum = conn.generateInitSeqNum()
	packetHdr.AckNum = 0
	packetHdr.Offset = 5
	packetHdr.Flags = SYN
	packetHdr.Window = 128
	packetHdr.Checksum = 0
	packetHdr.UrgentPtr = 0

	serTCPPack := serializeTCPPack(packetHdr)
	serPseudoHdr := serializePseudoIPHdr(conn.LocalAddr.Addr, conn.RemoteAddr.Addr, syscall.IPPROTO_TCP, uint16(len(serTCPPack)))

	// update checksum
	binary.BigEndian.PutUint16(serTCPPack[16:18], Checksum(append(serPseudoHdr, serTCPPack...)))

	err = conn.sendRaw(serTCPPack)
	if err != nil {
		fmt.Println("Error sending packet:", err)
		return err
	}

	buff := make([]byte, 1024)
	recvLen := int(0)
	buff, recvLen, err = conn.recvRaw(1024)

	if err != nil {
		fmt.Println("Error receiving packet:", err)
		return err
	}

	if recvLen > 0 {
		deserPack := deserializeTCPPack(buff)
		fmt.Println("recv back:%v", deserPack)
	} else {
		fmt.Println("Received empty buffer")
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
		fmt.Println("Local IP Format Error:", err)
		return err
	}

	remoteAddrBytes, err := IPStrtoBytes(remoteIPStr)

	if err != nil {
		fmt.Println("Remote IP Format Error:", err)
		return err
	}

	localAddrInt := syscall.SockaddrInet4{
		Addr: localAddrBytes,
		Port: int(localPort),
	}

	remoteAddrInt := syscall.SockaddrInet4{
		Addr: remoteAddrBytes,
		Port: int(remotePort),
	}

	err = syscall.Bind(fd, &localAddrInt)
	if err != nil {
		fmt.Printf("Error binding local address to socket:", err)
		return err
	}

	conn.Fd = fd
	conn.LocalAddr = localAddrInt
	conn.RemoteAddr = remoteAddrInt
	conn.Hdr.Src = localPort
	conn.Hdr.Dst = remotePort

	// TODO: call threeway handshare
	err = conn.initHandShake()
	return err
}

func (conn *TCPConn) Close() error {

	return syscall.Close(conn.Fd)
}

func (conn *TCPConn) sendRaw(data []byte) error {
	err := syscall.Sendto(conn.Fd, data, 0, &conn.RemoteAddr)
	if err != nil {
		fmt.Println("Error sending packet:", err)
	}
	return err
}

func (conn *TCPConn) recvRaw(size int) ([]byte, int, error) {
	buff := make([]byte, size)
	var err error
	var recvLen int
	var sockAddr syscall.Sockaddr
	for {
		recvLen, sockAddr, err = syscall.Recvfrom(conn.Fd, buff, 0)
		sockAddrInet4, _ := sockAddr.(*syscall.SockaddrInet4)
		if err == nil {
			if bytes.Equal(sockAddrInet4.Addr[:], conn.RemoteAddr.Addr[:]) {
				// remove IP header
				return buff[20:], recvLen, err
			} else {
				continue
			}
		} else {
			break
		}
	}
	return buff, 0, err
}

// func (conn *TCPConn) Abort() {
// }

// func (conn *TCPConn) Status() {
// }

func main() {

	var conn TCPConn
	err := conn.Open("10.68.186.2", 8080, "10.72.138.186", 50000)
	if err != nil {
		fmt.Println("Error opening connection:", err)
		return
	}
	err = conn.Close()
	if err != nil {
		fmt.Println("Failed to close connection:", err)
	}
}
