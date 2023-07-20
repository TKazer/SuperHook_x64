#include "SuperHook.h"

void SuperHook_x64::UnInstall()
{
	for (auto HookInfo : this->HookInfoList)
	{
		WriteBytes(this->ProcessHandle, HookInfo.HookAddress, HookInfo.OriginalCode);
		VirtualFreeEx(this->ProcessHandle, reinterpret_cast<LPVOID>(HookInfo.NewAddress), 0, MEM_RELEASE);
		VirtualFreeEx(this->ProcessHandle, reinterpret_cast<LPVOID>(HookInfo.RegisterAddress), 0, MEM_RELEASE);
		VirtualFreeEx(this->ProcessHandle, reinterpret_cast<LPVOID>(HookInfo.ProcessConnectAddress), 0, MEM_RELEASE);
	}
}

SuperHook_x64::~SuperHook_x64()
{
	for (auto HookInfo : this->HookInfoList)
	{
		WriteBytes(this->ProcessHandle, HookInfo.HookAddress, HookInfo.OriginalCode);
		VirtualFreeEx(this->ProcessHandle, reinterpret_cast<LPVOID>(HookInfo.NewAddress), 0, MEM_RELEASE);
		VirtualFreeEx(this->ProcessHandle, reinterpret_cast<LPVOID>(HookInfo.RegisterAddress), 0, MEM_RELEASE);
		VirtualFreeEx(this->ProcessHandle, reinterpret_cast<LPVOID>(HookInfo.ProcessConnectAddress), 0, MEM_RELEASE);
	}
}

bool SuperHook_x64::Pause(HookData Data)
{
	return WriteBytes(this->ProcessHandle, Data.OriginalAddress, Data.OriginalCode);
}

bool SuperHook_x64::Continue(HookData Data)
{
	return WriteBytes(this->ProcessHandle, Data.OriginalAddress, Data.HookCode);
}

Register SuperHook_x64::ReadAllRegister(DWORD64 ReAddress)
{
	Register Temp;
	if (ReadProcessMemory(this->ProcessHandle, (LPCVOID)ReAddress, &Temp, sizeof(Register), 0))
		return Temp;
	return Register{};
}

bool SuperHook_x64::Hook(HANDLE Handle, DWORD64 HookAddress, void* CallBack, HookData& InterceptData, size_t InterceptSize)
{
	if (InterceptSize < 14)
		return false;

	Bytes ShellCode;
	HookRecord HookInfo;

	this->ProcessHandle = Handle;
	HookInfo.HookAddress = HookAddress;
	InterceptData.OriginalAddress = HookAddress;

	HookInfo.NewAddress = reinterpret_cast<DWORD64>(VirtualAllocEx(Handle, 0, 1024, MEM_COMMIT, 64));
	HookInfo.RegisterAddress = reinterpret_cast<DWORD64>(VirtualAllocEx(Handle, 0, 1024, MEM_COMMIT, 64));

	InterceptData.ReturnRegisterAddress = HookInfo.RegisterAddress;

	HookInfo.OriginalCode = ReadBytes(Handle, HookAddress, InterceptSize);
	InterceptData.OriginalCode = HookInfo.OriginalCode;

	HookInfo.ProcessConnectAddress = reinterpret_cast<DWORD64>(VirtualAllocEx(Handle, 0, 32, MEM_COMMIT, 64));
	WriteBytes(Handle, HookInfo.ProcessConnectAddress, Bytes(GetCurrentProcessId()));

	this->HookInfoList.push_back(HookInfo);

	ShellCode = this->InitHookShellCode(HookInfo,CallBack);
	ShellCode += HookInfo.OriginalCode;
	ShellCode += Jmp(HookAddress + InterceptSize);

	// Ð´ÈëShellCode
	WriteBytes(Handle, HookInfo.NewAddress, ShellCode);
	InterceptData.HookCode = Jmp(HookInfo.NewAddress) + JmpComplementCode(InterceptSize);
	WriteBytes(Handle, HookAddress, InterceptData.HookCode);
	return true;
}

Bytes SuperHook_x64::InitHookShellCode(HookRecord HookInfo, void* CallBack)
{
	Bytes ShellCode;
	// mov function
	auto mov_1 = [&](byte register_, DWORD64 Address) -> Bytes {
		return Bytes{ 0x48, 0x89 } + Bytes{ register_ } + Bytes((DWORD)(Address - HookInfo.NewAddress - ShellCode.Length() - 7));
	};
	auto mov_2 = [&](byte register_, DWORD64 Address) -> Bytes {
		return Bytes{ 0x48, 0x8B } + Bytes{ register_ } + Bytes((DWORD)(Address - HookInfo.NewAddress - ShellCode.Length() - 7));
	};
	// mov register
	ShellCode += Bytes{0x48, 0xA3} + Bytes(HookInfo.RegisterAddress);
	ShellCode += mov_1(0x1D, HookInfo.RegisterAddress + 8);
	ShellCode += mov_1(0x15, HookInfo.RegisterAddress + 16);
	ShellCode += mov_1(0x0D, HookInfo.RegisterAddress + 24);
	ShellCode += mov_1(0x35, HookInfo.RegisterAddress + 32);
	ShellCode += mov_1(0x3D, HookInfo.RegisterAddress + 40);
	ShellCode += mov_1(0x25, HookInfo.RegisterAddress + 48);
	ShellCode += mov_1(0x2D, HookInfo.RegisterAddress + 56);
	
	// push register
	ShellCode += Bytes{0x50, 0x53, 0x52, 0x51, 0x56, 0x57, 0x55};

	// Call OpenProcess
	ShellCode += mov_2(0x05, HookInfo.ProcessConnectAddress);
	ShellCode += Bytes{0x48, 0xB9} + Bytes((DWORD64)0x1F0FFF);
	ShellCode += Bytes{0x48, 0xBA} + Bytes((DWORD64)0);
	ShellCode += Bytes{0x4C, 0x8B, 0xC0};
	ShellCode += Call(reinterpret_cast<DWORD64>(OpenProcess));
	ShellCode += Bytes{0x48, 0xA3} + Bytes(HookInfo.ProcessConnectAddress + 8);
	
	// Call CreateRemoteThread
	ShellCode += Bytes{0x48,0x8B,0xC8};
	ShellCode += Bytes{0x48, 0xBA} + Bytes((DWORD64)0);
	ShellCode += Bytes{0x49, 0xB8} + Bytes((DWORD64)0);
	ShellCode += Bytes{0x49, 0xB9} + Bytes((DWORD64)(CallBack));
	ShellCode += Bytes{0x6A, 0x00};
	ShellCode += Bytes{0x6A, 0x00};
	ShellCode += Bytes{0x6A, 0x00};
	ShellCode += Bytes{0x6A, 0x00};
	ShellCode += Call(reinterpret_cast<DWORD64>(CreateRemoteThread));
	ShellCode += Bytes{0x48, 0xA3} + Bytes(HookInfo.ProcessConnectAddress + 24);
	
	// Call WaitForSingleObject
	ShellCode += Bytes{0x48, 0x8B, 0xC8};
	ShellCode += Bytes{0x48, 0xBA} + Bytes((DWORD64)0xFFFFFFFF);
	ShellCode += Call(reinterpret_cast<DWORD64>(WaitForSingleObject));
	
	// Call CloseHandle
	ShellCode += mov_2(0x0D, HookInfo.ProcessConnectAddress + 24);
	ShellCode += Call(reinterpret_cast<DWORD64>(CloseHandle));
	
	ShellCode += mov_2(0x0D, HookInfo.ProcessConnectAddress + 8);
	ShellCode += Call(reinterpret_cast<DWORD64>(CloseHandle));

	// pop register
	ShellCode += Bytes{0x5D, 0x5F, 0x5E, 0x59, 0x5A, 0x5B, 0x58};

	return ShellCode;
}
/*
191AB850000 - 48 A3 000086AB91010000 - mov [191AB860000],rax
191AB85000A - 48 89 1D F7FF0000     - mov [191AB860008],rbx
191AB850011 - 48 89 15 F8FF0000     - mov [191AB860010],rdx
191AB850018 - 48 89 0D F9FF0000     - mov [191AB860018],rcx
191AB85001F - 48 89 35 FAFF0000     - mov [191AB860020],rsi
191AB850026 - 48 89 3D FBFF0000     - mov [191AB860028],rdi
191AB85002D - 48 89 25 FCFF0000     - mov [191AB860030],rsp
191AB850034 - 48 89 2D FDFF0000     - mov [191AB860038],rbp
191AB85003B - 50                    - push rax
191AB85003C - 53                    - push rbx
191AB85003D - 52                    - push rdx
191AB85003E - 51                    - push rcx
191AB85003F - 56                    - push rsi
191AB850040 - 57                    - push rdi
191AB850041 - 55                    - push rbp
191AB850042 - 48 8B 05 B7FF0100     - mov rax,[191AB870000]
191AB850049 - 48 B9 FF0F1F0000000000 - mov rcx,00000000001F0FFF
191AB850053 - 48 BA 0000000000000000 - mov rdx,0000000000000000
191AB85005D - 4C 8B C0              - mov r8,rax
191AB850060 - FF15 02000000 EB08 70B58D73FC7F0000 - call KERNEL32.OpenProcess
191AB850070 - 48 A3 080087AB91010000 - mov [191AB870008],rax
191AB85007A - 48 8B C8              - mov rcx,rax
191AB85007D - 48 BA 0000000000000000 - mov rdx,0000000000000000
191AB850087 - 49 B8 0000000000000000 - mov r8,0000000000000000
191AB850091 - 49 B9 4020C6A2F77F0000 - mov r9,00007FF7A2C62040
191AB85009B - 6A 00                 - push 00
191AB85009D - 6A 00                 - push 00
191AB85009F - 6A 00                 - push 00
191AB8500A1 - 6A 00                 - push 00
191AB8500A3 - FF15 02000000 EB08 90B18F73FC7F0000 - call KERNEL32.CreateRemoteThread
191AB8500B3 - 48 A3 180087AB91010000 - mov [191AB870018],rax
191AB8500BD - 48 8B C8              - mov rcx,rax
191AB8500C0 - 48 BA FFFFFFFF00000000 - mov rdx,00000000FFFFFFFF
191AB8500CA - FF15 02000000 EB08 50528E73FC7F0000 - call KERNEL32.WaitForSingleObject
191AB8500DA - 48 8B 0D 37FF0100     - mov rcx,[191AB870018]
191AB8500E1 - FF15 02000000 EB08 60508E73FC7F0000 - call KERNEL32.CloseHandle
191AB8500F1 - 48 8B 0D 10FF0100     - mov rcx,[191AB870008]
191AB8500F8 - FF15 02000000 EB08 60508E73FC7F0000 - call KERNEL32.CloseHandle
191AB850108 - 5D                    - pop rbp
191AB850109 - 5F                    - pop rdi
191AB85010A - 5E                    - pop rsi
191AB85010B - 59                    - pop rcx
191AB85010C - 5A                    - pop rdx
191AB85010D - 5B                    - pop rbx
191AB85010E - 58                    - pop rax
*/

Bytes SuperHook_x64::Call(DWORD64 Address)
{
	Bytes Code;
	Code += Bytes({ 0xFF,0x15,0x02,0x00,0x00,0x00,0xEB,0x08 });
	Code += Bytes(Address);
	return Code;
}

Bytes SuperHook_x64::Jmp(DWORD64 Address)
{
	Bytes Code;
	Code += Bytes({ 0xFF,0x25,0x00,0x00,0x00,0x00 });
	Code += Bytes(Address);
	return Code;
}

Bytes SuperHook_x64::JmpComplementCode(size_t Size)
{
	Bytes Code;
	if (Size == 14)
		return Bytes();
	for (int i = 0; i < Size - 14; i++)
		Code.Add(144);
	return Code;
}

Bytes SuperHook_x64::ReadBytes(HANDLE Handle, DWORD64 Address, size_t Size)
{
	byte* Data = new byte[Size];
	Bytes Result;

	DWORD OldProtect = 0;
	VirtualProtectEx(Handle, (LPVOID)Address, Size, PAGE_EXECUTE_READWRITE, &OldProtect);
	
	if (ReadProcessMemory(Handle, reinterpret_cast<LPCVOID>(Address), Data, Size, 0))
	{
		Result = Bytes(Data, Size);
		VirtualProtectEx(Handle, (LPVOID)Address, Size, OldProtect, &OldProtect);
		delete[] Data;
		return Result;
	}
	VirtualProtectEx(Handle, (LPVOID)Address, Size, OldProtect, &OldProtect);
	delete[] Data;
	return Bytes();
}

bool SuperHook_x64::WriteBytes(HANDLE Handle, DWORD64 Address, Bytes WriteData)
{
	byte* Data = new byte[WriteData.Length()];
	for (int i = 0; i < WriteData.Length(); i++)
		Data[i] = WriteData.Data[i];

	DWORD OldProtect = 0;
	VirtualProtectEx(Handle, (LPVOID)Address, WriteData.Length(), PAGE_EXECUTE_READWRITE, &OldProtect);

	if (WriteProcessMemory(Handle, reinterpret_cast<LPVOID>(Address), Data, WriteData.Length(), 0))
	{
		VirtualProtectEx(Handle, (LPVOID)Address, WriteData.Length(), OldProtect, &OldProtect);
		delete[] Data;
		return true;
	}
	VirtualProtectEx(Handle, (LPVOID)Address, WriteData.Length(), OldProtect, &OldProtect);

	delete[] Data;
	return false;
}
