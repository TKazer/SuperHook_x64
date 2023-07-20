#include "SuperHook.h"
#include "ProcessManager.hpp"

/*
	@Liv github.com/TKazer
*/

HookData Data;
SuperHook_x64 Obj;

void HookCallBack()
{
	auto RegisterData = Obj.ReadAllRegister(Data.ReturnRegisterAddress);
	std::cout << "rax:" << std::hex << RegisterData.rax << std::endl;
	std::cout << "rbx:" << std::hex << RegisterData.rbx << std::endl;
	std::cout << "rdx:" << std::hex << RegisterData.rdx << std::endl;
	std::cout << "rcx:" << std::hex << RegisterData.rcx << std::endl;
	std::cout << "rsi:" << std::hex << RegisterData.rsi << std::endl;
	std::cout << "rbp:" << std::hex << RegisterData.rbp << std::endl;
	std::cout << "rdi:" << std::hex << RegisterData.rdi << std::endl;
}

int main()
{
	HANDLE ProcessHandle = 0;
	DWORD64 HookAddress = 0;
	size_t HookCodeSize = 0;
	ProcessMgr.Attach("a.exe");
	
	ProcessHandle = ProcessMgr.hProcess;

	Obj.Hook(ProcessHandle, HookAddress, HookCallBack, Data, HookCodeSize);

	while (true) 
	{
		if (GetAsyncKeyState(VK_END))
		{
			Obj.UnInstall();
			break;
		}
	};
	system("pause");
	return 0;
}