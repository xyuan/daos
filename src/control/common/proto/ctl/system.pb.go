// Code generated by protoc-gen-go. DO NOT EDIT.
// source: system.proto

package ctl

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// SystemMember refers to a data-plane instance that is a member of DAOS
// system running on host with the control-plane listening at "Addr".
type SystemMember struct {
	Addr                 string   `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
	Uuid                 string   `protobuf:"bytes,2,opt,name=uuid,proto3" json:"uuid,omitempty"`
	Rank                 uint32   `protobuf:"varint,3,opt,name=rank,proto3" json:"rank,omitempty"`
	State                uint32   `protobuf:"varint,4,opt,name=state,proto3" json:"state,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SystemMember) Reset()         { *m = SystemMember{} }
func (m *SystemMember) String() string { return proto.CompactTextString(m) }
func (*SystemMember) ProtoMessage()    {}
func (*SystemMember) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{0}
}

func (m *SystemMember) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemMember.Unmarshal(m, b)
}
func (m *SystemMember) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemMember.Marshal(b, m, deterministic)
}
func (m *SystemMember) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemMember.Merge(m, src)
}
func (m *SystemMember) XXX_Size() int {
	return xxx_messageInfo_SystemMember.Size(m)
}
func (m *SystemMember) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemMember.DiscardUnknown(m)
}

var xxx_messageInfo_SystemMember proto.InternalMessageInfo

func (m *SystemMember) GetAddr() string {
	if m != nil {
		return m.Addr
	}
	return ""
}

func (m *SystemMember) GetUuid() string {
	if m != nil {
		return m.Uuid
	}
	return ""
}

func (m *SystemMember) GetRank() uint32 {
	if m != nil {
		return m.Rank
	}
	return 0
}

func (m *SystemMember) GetState() uint32 {
	if m != nil {
		return m.State
	}
	return 0
}

// RankResult is a generic result for a system operation on a rank.
// Identical to mgmt.proto RanksResp_RankResult.
type RankResult struct {
	Rank                 uint32   `protobuf:"varint,1,opt,name=rank,proto3" json:"rank,omitempty"`
	Action               string   `protobuf:"bytes,2,opt,name=action,proto3" json:"action,omitempty"`
	Errored              bool     `protobuf:"varint,3,opt,name=errored,proto3" json:"errored,omitempty"`
	Msg                  string   `protobuf:"bytes,4,opt,name=msg,proto3" json:"msg,omitempty"`
	State                uint32   `protobuf:"varint,5,opt,name=state,proto3" json:"state,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RankResult) Reset()         { *m = RankResult{} }
func (m *RankResult) String() string { return proto.CompactTextString(m) }
func (*RankResult) ProtoMessage()    {}
func (*RankResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{1}
}

func (m *RankResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RankResult.Unmarshal(m, b)
}
func (m *RankResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RankResult.Marshal(b, m, deterministic)
}
func (m *RankResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RankResult.Merge(m, src)
}
func (m *RankResult) XXX_Size() int {
	return xxx_messageInfo_RankResult.Size(m)
}
func (m *RankResult) XXX_DiscardUnknown() {
	xxx_messageInfo_RankResult.DiscardUnknown(m)
}

var xxx_messageInfo_RankResult proto.InternalMessageInfo

func (m *RankResult) GetRank() uint32 {
	if m != nil {
		return m.Rank
	}
	return 0
}

func (m *RankResult) GetAction() string {
	if m != nil {
		return m.Action
	}
	return ""
}

func (m *RankResult) GetErrored() bool {
	if m != nil {
		return m.Errored
	}
	return false
}

func (m *RankResult) GetMsg() string {
	if m != nil {
		return m.Msg
	}
	return ""
}

func (m *RankResult) GetState() uint32 {
	if m != nil {
		return m.State
	}
	return 0
}

// SystemStopReq supplies system shutdown parameters.
type SystemStopReq struct {
	Prep                 bool     `protobuf:"varint,1,opt,name=prep,proto3" json:"prep,omitempty"`
	Kill                 bool     `protobuf:"varint,2,opt,name=kill,proto3" json:"kill,omitempty"`
	Force                bool     `protobuf:"varint,3,opt,name=force,proto3" json:"force,omitempty"`
	Ranks                []uint32 `protobuf:"varint,4,rep,packed,name=ranks,proto3" json:"ranks,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SystemStopReq) Reset()         { *m = SystemStopReq{} }
func (m *SystemStopReq) String() string { return proto.CompactTextString(m) }
func (*SystemStopReq) ProtoMessage()    {}
func (*SystemStopReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{2}
}

func (m *SystemStopReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemStopReq.Unmarshal(m, b)
}
func (m *SystemStopReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemStopReq.Marshal(b, m, deterministic)
}
func (m *SystemStopReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemStopReq.Merge(m, src)
}
func (m *SystemStopReq) XXX_Size() int {
	return xxx_messageInfo_SystemStopReq.Size(m)
}
func (m *SystemStopReq) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemStopReq.DiscardUnknown(m)
}

var xxx_messageInfo_SystemStopReq proto.InternalMessageInfo

func (m *SystemStopReq) GetPrep() bool {
	if m != nil {
		return m.Prep
	}
	return false
}

func (m *SystemStopReq) GetKill() bool {
	if m != nil {
		return m.Kill
	}
	return false
}

func (m *SystemStopReq) GetForce() bool {
	if m != nil {
		return m.Force
	}
	return false
}

func (m *SystemStopReq) GetRanks() []uint32 {
	if m != nil {
		return m.Ranks
	}
	return nil
}

// SystemStopResp returns status of shutdown attempt and results
// of attempts to stop system members.
type SystemStopResp struct {
	Results              []*RankResult `protobuf:"bytes,1,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *SystemStopResp) Reset()         { *m = SystemStopResp{} }
func (m *SystemStopResp) String() string { return proto.CompactTextString(m) }
func (*SystemStopResp) ProtoMessage()    {}
func (*SystemStopResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{3}
}

func (m *SystemStopResp) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemStopResp.Unmarshal(m, b)
}
func (m *SystemStopResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemStopResp.Marshal(b, m, deterministic)
}
func (m *SystemStopResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemStopResp.Merge(m, src)
}
func (m *SystemStopResp) XXX_Size() int {
	return xxx_messageInfo_SystemStopResp.Size(m)
}
func (m *SystemStopResp) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemStopResp.DiscardUnknown(m)
}

var xxx_messageInfo_SystemStopResp proto.InternalMessageInfo

func (m *SystemStopResp) GetResults() []*RankResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// SystemStartReq supplies system restart parameters.
type SystemStartReq struct {
	Ranks                []uint32 `protobuf:"varint,1,rep,packed,name=ranks,proto3" json:"ranks,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SystemStartReq) Reset()         { *m = SystemStartReq{} }
func (m *SystemStartReq) String() string { return proto.CompactTextString(m) }
func (*SystemStartReq) ProtoMessage()    {}
func (*SystemStartReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{4}
}

func (m *SystemStartReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemStartReq.Unmarshal(m, b)
}
func (m *SystemStartReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemStartReq.Marshal(b, m, deterministic)
}
func (m *SystemStartReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemStartReq.Merge(m, src)
}
func (m *SystemStartReq) XXX_Size() int {
	return xxx_messageInfo_SystemStartReq.Size(m)
}
func (m *SystemStartReq) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemStartReq.DiscardUnknown(m)
}

var xxx_messageInfo_SystemStartReq proto.InternalMessageInfo

func (m *SystemStartReq) GetRanks() []uint32 {
	if m != nil {
		return m.Ranks
	}
	return nil
}

// SystemStartResp returns status of restart attempt and results
// of attempts to start system members.
type SystemStartResp struct {
	Results              []*RankResult `protobuf:"bytes,1,rep,name=results,proto3" json:"results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *SystemStartResp) Reset()         { *m = SystemStartResp{} }
func (m *SystemStartResp) String() string { return proto.CompactTextString(m) }
func (*SystemStartResp) ProtoMessage()    {}
func (*SystemStartResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{5}
}

func (m *SystemStartResp) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemStartResp.Unmarshal(m, b)
}
func (m *SystemStartResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemStartResp.Marshal(b, m, deterministic)
}
func (m *SystemStartResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemStartResp.Merge(m, src)
}
func (m *SystemStartResp) XXX_Size() int {
	return xxx_messageInfo_SystemStartResp.Size(m)
}
func (m *SystemStartResp) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemStartResp.DiscardUnknown(m)
}

var xxx_messageInfo_SystemStartResp proto.InternalMessageInfo

func (m *SystemStartResp) GetResults() []*RankResult {
	if m != nil {
		return m.Results
	}
	return nil
}

// SystemQueryReq supplies system query parameters.
type SystemQueryReq struct {
	Ranks                []uint32 `protobuf:"varint,1,rep,packed,name=ranks,proto3" json:"ranks,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SystemQueryReq) Reset()         { *m = SystemQueryReq{} }
func (m *SystemQueryReq) String() string { return proto.CompactTextString(m) }
func (*SystemQueryReq) ProtoMessage()    {}
func (*SystemQueryReq) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{6}
}

func (m *SystemQueryReq) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemQueryReq.Unmarshal(m, b)
}
func (m *SystemQueryReq) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemQueryReq.Marshal(b, m, deterministic)
}
func (m *SystemQueryReq) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemQueryReq.Merge(m, src)
}
func (m *SystemQueryReq) XXX_Size() int {
	return xxx_messageInfo_SystemQueryReq.Size(m)
}
func (m *SystemQueryReq) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemQueryReq.DiscardUnknown(m)
}

var xxx_messageInfo_SystemQueryReq proto.InternalMessageInfo

func (m *SystemQueryReq) GetRanks() []uint32 {
	if m != nil {
		return m.Ranks
	}
	return nil
}

// SystemQueryResp returns active system members.
type SystemQueryResp struct {
	Members              []*SystemMember `protobuf:"bytes,1,rep,name=members,proto3" json:"members,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *SystemQueryResp) Reset()         { *m = SystemQueryResp{} }
func (m *SystemQueryResp) String() string { return proto.CompactTextString(m) }
func (*SystemQueryResp) ProtoMessage()    {}
func (*SystemQueryResp) Descriptor() ([]byte, []int) {
	return fileDescriptor_86a7260ebdc12f47, []int{7}
}

func (m *SystemQueryResp) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SystemQueryResp.Unmarshal(m, b)
}
func (m *SystemQueryResp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SystemQueryResp.Marshal(b, m, deterministic)
}
func (m *SystemQueryResp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SystemQueryResp.Merge(m, src)
}
func (m *SystemQueryResp) XXX_Size() int {
	return xxx_messageInfo_SystemQueryResp.Size(m)
}
func (m *SystemQueryResp) XXX_DiscardUnknown() {
	xxx_messageInfo_SystemQueryResp.DiscardUnknown(m)
}

var xxx_messageInfo_SystemQueryResp proto.InternalMessageInfo

func (m *SystemQueryResp) GetMembers() []*SystemMember {
	if m != nil {
		return m.Members
	}
	return nil
}

func init() {
	proto.RegisterType((*SystemMember)(nil), "ctl.SystemMember")
	proto.RegisterType((*RankResult)(nil), "ctl.RankResult")
	proto.RegisterType((*SystemStopReq)(nil), "ctl.SystemStopReq")
	proto.RegisterType((*SystemStopResp)(nil), "ctl.SystemStopResp")
	proto.RegisterType((*SystemStartReq)(nil), "ctl.SystemStartReq")
	proto.RegisterType((*SystemStartResp)(nil), "ctl.SystemStartResp")
	proto.RegisterType((*SystemQueryReq)(nil), "ctl.SystemQueryReq")
	proto.RegisterType((*SystemQueryResp)(nil), "ctl.SystemQueryResp")
}

func init() {
	proto.RegisterFile("system.proto", fileDescriptor_86a7260ebdc12f47)
}

var fileDescriptor_86a7260ebdc12f47 = []byte{
	// 309 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x92, 0xbf, 0x4e, 0xc3, 0x30,
	0x10, 0xc6, 0x65, 0xd2, 0xbf, 0x47, 0x4b, 0xc1, 0x42, 0xc8, 0x63, 0x94, 0x01, 0x15, 0x21, 0x75,
	0x80, 0x11, 0xc4, 0x1b, 0x30, 0xe0, 0xbe, 0x00, 0x6e, 0x62, 0x50, 0x94, 0x3f, 0x36, 0x67, 0x67,
	0x28, 0x4f, 0x8f, 0x7c, 0x49, 0x9a, 0x30, 0xb0, 0xb0, 0x7d, 0xdf, 0x97, 0xbb, 0xfc, 0xee, 0xac,
	0x83, 0x95, 0x3b, 0x3a, 0xaf, 0xab, 0x9d, 0x45, 0xe3, 0x0d, 0x8f, 0x52, 0x5f, 0x26, 0xef, 0xb0,
	0xda, 0x53, 0xf8, 0xaa, 0xab, 0x83, 0x46, 0xce, 0x61, 0xa2, 0xb2, 0x0c, 0x05, 0x8b, 0xd9, 0x76,
	0x29, 0x49, 0x87, 0xac, 0x69, 0xf2, 0x4c, 0x9c, 0xb5, 0x59, 0xd0, 0x21, 0x43, 0x55, 0x17, 0x22,
	0x8a, 0xd9, 0x76, 0x2d, 0x49, 0xf3, 0x6b, 0x98, 0x3a, 0xaf, 0xbc, 0x16, 0x13, 0x0a, 0x5b, 0x93,
	0x7c, 0x03, 0x48, 0x55, 0x17, 0x52, 0xbb, 0xa6, 0xf4, 0xa7, 0x3e, 0x36, 0xea, 0xbb, 0x81, 0x99,
	0x4a, 0x7d, 0x6e, 0xea, 0x8e, 0xd0, 0x39, 0x2e, 0x60, 0xae, 0x11, 0x0d, 0xea, 0x8c, 0x30, 0x0b,
	0xd9, 0x5b, 0x7e, 0x09, 0x51, 0xe5, 0x3e, 0x89, 0xb3, 0x94, 0x41, 0x0e, 0xec, 0xe9, 0x98, 0x9d,
	0xc2, 0xba, 0xdd, 0x6e, 0xef, 0x8d, 0x95, 0xfa, 0x2b, 0xe0, 0x2d, 0x6a, 0x4b, 0xf8, 0x85, 0x24,
	0x1d, 0xb2, 0x22, 0x2f, 0x4b, 0x82, 0x2f, 0x24, 0xe9, 0xf0, 0xbb, 0x0f, 0x83, 0xa9, 0xee, 0xc0,
	0xad, 0x09, 0x69, 0x18, 0xd8, 0x89, 0x49, 0x1c, 0x05, 0x08, 0x99, 0xe4, 0x09, 0x2e, 0xc6, 0x10,
	0x67, 0xf9, 0x1d, 0xcc, 0x91, 0xd6, 0x75, 0x82, 0xc5, 0xd1, 0xf6, 0xfc, 0x61, 0xb3, 0x4b, 0x7d,
	0xb9, 0x1b, 0x9e, 0x41, 0xf6, 0xdf, 0x93, 0xdb, 0xa1, 0x59, 0xa1, 0x0f, 0x23, 0x9e, 0x20, 0x6c,
	0x0c, 0x79, 0x86, 0xcd, 0xaf, 0xba, 0x7f, 0x52, 0xde, 0x1a, 0x8d, 0xc7, 0xbf, 0x29, 0x2f, 0x3d,
	0xa5, 0xab, 0x73, 0x96, 0xdf, 0xc3, 0xbc, 0xa2, 0xd3, 0xe8, 0x29, 0x57, 0x44, 0x19, 0x1f, 0x8d,
	0xec, 0x2b, 0x0e, 0x33, 0xba, 0xac, 0xc7, 0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0e, 0x9c, 0xec,
	0x70, 0x69, 0x02, 0x00, 0x00,
}