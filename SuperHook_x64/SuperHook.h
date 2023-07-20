#pragma once
#include "BytesManager.h"

/*
	@Liv github.com/TKazer
*/

// 结构 - Hook数据
struct HookData {
	DWORD64 ReturnRegisterAddress = 0;			// 返回地址
	Bytes OriginalCode;				// 原始数据
	DWORD64 OriginalAddress = 0;	// 原始地址
	Bytes HookCode;					// Hook数据
};

// 结构 - Hook信息记录
struct HookRecord {
	DWORD64 HookAddress = 0;			// Hook地址
	Bytes OriginalCode;					// 原始数据
	Bytes HookCode;						// Hook数据
	DWORD64 NewAddress = 0;				// 新地址
	DWORD64 RegisterAddress = 0;		// 寄存器地址
	DWORD64 ProcessConnectAddress = 0;	// 连接地址
};

// 结构 - 寄存器结构
struct Register
{
	DWORD64 rax;
	DWORD64 rbx;
	DWORD64 rdx;
	DWORD64 rcx;
	DWORD64 rsi;
	DWORD64 rdi;
	DWORD64 rbp;
};

// 类 - 内存超级Hook_x64
class SuperHook_x64
{
public:
	// 析构函数
	~SuperHook_x64();
	// 目标进程句柄
	HANDLE ProcessHandle;
	// Hook信息记录
	std::vector<HookRecord> HookInfoList;

	// 开始Hook
	/**
	* @param Handle				目标进程句柄
	* @param HookAddress		Hook地址
	* @param CallBack			回调
	* @param InterceptData		拦截数据
	* @param InterceptSize		拦截大小
	* @ps : 至少占用14字节
	**/
	bool Hook(HANDLE Handle, DWORD64 HookAddress, void* CallBack, HookData& InterceptData, size_t InterceptSize);
	// 卸载所有Hook
	void UnInstall();
	// 暂停Hook
	bool Pause(HookData Data);
	// 继续Hook
	bool Continue(HookData Data);
	// 读取返回地址寄存器数据
	Register ReadAllRegister(DWORD64 ReAddress);
private:
	// 初始代码
	Bytes InitHookShellCode(HookRecord HookInfo, void* CallBack);
	// 读取Bytes数据
	Bytes ReadBytes(HANDLE Handle, DWORD64 Address, size_t Size);
	// 写入Bytes数据
	bool WriteBytes(HANDLE Handle, DWORD64 Address, Bytes WriteData);
	// Call
	Bytes Call(DWORD64 Address);
	Bytes Jmp(DWORD64 Address);
	Bytes JmpComplementCode(size_t Size);
};
