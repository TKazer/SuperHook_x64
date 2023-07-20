#pragma once
#include "BytesManager.h"

/*
	@Liv github.com/TKazer
*/

// �ṹ - Hook����
struct HookData {
	DWORD64 ReturnRegisterAddress = 0;			// ���ص�ַ
	Bytes OriginalCode;				// ԭʼ����
	DWORD64 OriginalAddress = 0;	// ԭʼ��ַ
	Bytes HookCode;					// Hook����
};

// �ṹ - Hook��Ϣ��¼
struct HookRecord {
	DWORD64 HookAddress = 0;			// Hook��ַ
	Bytes OriginalCode;					// ԭʼ����
	Bytes HookCode;						// Hook����
	DWORD64 NewAddress = 0;				// �µ�ַ
	DWORD64 RegisterAddress = 0;		// �Ĵ�����ַ
	DWORD64 ProcessConnectAddress = 0;	// ���ӵ�ַ
};

// �ṹ - �Ĵ����ṹ
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

// �� - �ڴ泬��Hook_x64
class SuperHook_x64
{
public:
	// ��������
	~SuperHook_x64();
	// Ŀ����̾��
	HANDLE ProcessHandle;
	// Hook��Ϣ��¼
	std::vector<HookRecord> HookInfoList;

	// ��ʼHook
	/**
	* @param Handle				Ŀ����̾��
	* @param HookAddress		Hook��ַ
	* @param CallBack			�ص�
	* @param InterceptData		��������
	* @param InterceptSize		���ش�С
	* @ps : ����ռ��14�ֽ�
	**/
	bool Hook(HANDLE Handle, DWORD64 HookAddress, void* CallBack, HookData& InterceptData, size_t InterceptSize);
	// ж������Hook
	void UnInstall();
	// ��ͣHook
	bool Pause(HookData Data);
	// ����Hook
	bool Continue(HookData Data);
	// ��ȡ���ص�ַ�Ĵ�������
	Register ReadAllRegister(DWORD64 ReAddress);
private:
	// ��ʼ����
	Bytes InitHookShellCode(HookRecord HookInfo, void* CallBack);
	// ��ȡBytes����
	Bytes ReadBytes(HANDLE Handle, DWORD64 Address, size_t Size);
	// д��Bytes����
	bool WriteBytes(HANDLE Handle, DWORD64 Address, Bytes WriteData);
	// Call
	Bytes Call(DWORD64 Address);
	Bytes Jmp(DWORD64 Address);
	Bytes JmpComplementCode(size_t Size);
};
