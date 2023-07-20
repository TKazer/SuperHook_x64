#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>

/*
	@Liv github.com/TKazer
*/

//�� - �ֽڹ���
class Bytes
{

public:
	std::vector<byte> Data;
	// Ĭ�Ϲ���
	Bytes() {}
	// ���ֽ�ָ��ʹ�С��ʼ��d
	Bytes(const byte* _In, size_t Size);
	// ���ֽڼ��ϳ�ʼ��
	Bytes(std::initializer_list<byte> _In);
	// �������ͳ�ʼ���ֽ�����
	Bytes(const DWORD& _In);
	// �Գ������ͳ�ʼ���ֽ�����
	Bytes(const DWORD64& _In);
	// �Ի������ַ�����ʼ���ֽ�����
	Bytes(const std::string& _In);
	// ���������
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

	// ����ֽ�
	Bytes& Add(const byte _In);
	// �����ֽ������С
	int Length();
	// �滻�ֽ�����
	bool Replace(int Index, int Length, Bytes Source);
	// Ѱ���ֽ�����
	int Find(Bytes Source, int Index = 0);
	// ȡ�м��ֽ�����
	Bytes Get(int Index, int Length);
	byte* GetData();
	// ����ֽ�����
	void Print();
};
