#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>

/*
	@Liv github.com/TKazer
*/

//类 - 字节管理
class Bytes
{

public:
	std::vector<byte> Data;
	// 默认构造
	Bytes() {}
	// 以字节指针和大小初始化d
	Bytes(const byte* _In, size_t Size);
	// 以字节集合初始化
	Bytes(std::initializer_list<byte> _In);
	// 以整数型初始化字节数组
	Bytes(const DWORD& _In);
	// 以长整数型初始化字节数组
	Bytes(const DWORD64& _In);
	// 以机器码字符串初始化字节数组
	Bytes(const std::string& _In);
	// 重载运算符
	bool operator!=(Bytes _In)
	{
		for (int i = 0; i < _In.Length(); i++)
		{
			if (this->Data[i] != _In.Data[i])
				return true;
		}
		return false;
	}
	bool operator==(Bytes _In)
	{
		for (int i = 0; i < _In.Length(); i++)
		{
			if (this->Data[i] != _In.Data[i])
				return false;
		}
		return true;
	}
	void operator=(Bytes _In)
	{
		Data.clear();
		for (int i = 0; i < _In.Length(); i++)
			this->Data.push_back(_In.Data[i]);
	}
	void operator+=(Bytes _In)
	{
		for (int i = 0; i < _In.Length(); i++)
			this->Data.push_back(_In.Data[i]);
	}
	Bytes& operator+(Bytes _In)
	{
		for (int i = 0; i < _In.Length(); i++)
			this->Data.push_back(_In.Data[i]);
		return *this;
	}

	// 添加字节
	Bytes& Add(const byte _In);
	// 返回字节数组大小
	int Length();
	// 替换字节数据
	bool Replace(int Index, int Length, Bytes Source);
	// 寻找字节数据
	int Find(Bytes Source, int Index = 0);
	// 取中间字节数据
	Bytes Get(int Index, int Length);
	byte* GetData();
	// 输出字节数组
	void Print();
};
