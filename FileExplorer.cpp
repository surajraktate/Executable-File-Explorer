#include<stdio.h>
#include<windows.h>
#include<iomanip>
#include<stdlib.h>
#include<io.h>
#include<fcntl.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<conio.h>
#include<iostream>
using namespace std;

long int OffDosHeader = 0;
long int OffFileHeader = 0;
long int OffOptHeader = 0;
long int OffSetHeader = 0;
void CalculateOffset(int fd)
{
	IMAGE_DOS_HEADER dosheader;
	_read(fd,&dosheader,sizeof(dosheader));
	OffDosHeader =0;
	OffFileHeader=dosheader.e_lfanew + 4;
	OffOptHeader = OffFileHeader + 0x14;
	OffSetHeader = OffOptHeader+sizeof(IMAGE_OPTIONAL_HEADER);

	_lseek(fd,0,0);
}
class dos_header
{
public:
		IMAGE_DOS_HEADER dosheader;
		int fp;
		dos_header(int f)
		{
			fp =f;
			_lseek(fp,OffDosHeader,0);
			_read(f,&dosheader,sizeof(dosheader));
		}

		void show_header()
		{
			cout<<endl<<"------------------DOS HEADER INFO--------------------"<<endl;
			cout<<"Magic number:"<<std::hex<<dosheader.e_magic<<endl;
			cout<<"Bytes on last page of file : "<<dosheader.e_cblp<<endl;
			cout<<"Pages in file : "<<dosheader.e_cp<<endl;
			cout<<"Relocation: "<<dosheader.e_crlc<<endl;
			cout<<"Size of header in paragraphs: "<<dosheader.e_cparhdr<<endl;
			cout<<"Minimum extra paragraph needed: "<<dosheader.e_minalloc<<endl;
			cout<<"Initial(relative)SS value: "<<dosheader.e_ss<<endl;
			cout<<"Initial SP value: "<<dosheader.e_sp<<endl;
			cout<<"Checksum: "<<dosheader.e_csum<<endl;
			cout<<"Initial IP value: "<<dosheader.e_ip<<endl;
			cout<<"Initial(relative)CS value: "<<dosheader.e_cs<<endl;
			cout<<"File address of relocation table : "<<dosheader.e_lfarlc<<endl;
			cout<<"Overlay number : "<<dosheader.e_ovno<<endl;
			cout<<"OEM idetifier : "<<dosheader.e_oemid<<endl;
			cout<<"OEM information(e_oemid specific): "<<dosheader.e_oeminfo<<endl;
			cout<<"RVA address of PE header: "<<dosheader.e_lfanew<<endl;
		}
};
class file_header
{
public:
	IMAGE_FILE_HEADER fileHeader;
	int fp;

	file_header(int f)
	{
		fp=f;
		_lseek(fp,OffFileHeader,0);
		_read(f,&fileHeader,sizeof(fileHeader));
	}
	void show_header()
	{
		cout<<endl<<"---------------FILE HEADER INFO------------"<<endl;
		cout<<"Machine :"<<fileHeader.Machine<<endl;
		cout<<"Number Of Sections : "<<fileHeader.NumberOfSections<<endl;
		cout<<"Time Date Stamp : "<<fileHeader.TimeDateStamp<<endl;
		cout<<"Pointer to symbol table : "<<fileHeader.PointerToSymbolTable<<endl;
		cout<<"Number Of Symbols : "<<fileHeader.NumberOfSymbols<<endl;
		cout<<"Size Of Optional Header : "<<fileHeader.SizeOfOptionalHeader<<endl;
		cout<<"Characteristics : "<<fileHeader.Characteristics<<endl;
	}
};
class opt_header
{
public:
		IMAGE_OPTIONAL_HEADER optHeader;
		int fp;
		opt_header(int f)
		{
			fp=f;
		_lseek(fp,OffOptHeader,0);
		_read(f,&optHeader,sizeof(optHeader));
		}
		void show_header()
		{
			cout<<endl<<"---------------OPTIONAL HEADER INFO------------"<<endl;
			cout<<"Magic: "<<optHeader.Magic<<endl;
			cout<<"Size	Of code: "<<optHeader.SizeOfCode<<endl;
			cout<<"Size Of Size Of Initialized Data: "<<optHeader.SizeOfInitializedData<<endl;
			cout<<"Size Of Size Of Uninitialized Data: "<<optHeader.SizeOfUninitializedData<<endl;
			cout<<"Address Of Entry Point: "<<optHeader.AddressOfEntryPoint<<endl;
			cout<<"Base Of Code: "<<optHeader.BaseOfCode<<endl;
			cout<<"Base Of Data: "<<optHeader.BaseOfData<<endl;
			cout<<"Image Base: "<<optHeader.ImageBase<<endl;
			cout<<"Section Alignment: "<<optHeader.SectionAlignment<<endl;
			cout<<"File Alignment: "<<optHeader.FileAlignment<<endl;
			cout<<"Major Operating System Version:  "<<optHeader.MajorOperatingSystemVersion<<endl;
			cout<<"Minor Operating System Version: "<<optHeader.MinorOperatingSystemVersion<<endl;
			cout<<"Major Image Version : "<<optHeader.MajorImageVersion<<endl;
			cout<<"Minor Image Version: "<<optHeader.MinorImageVersion<<endl;
			cout<<"Major Subsystem Version: "<<optHeader.MajorSubsystemVersion<<endl;
			cout<<"Minor Subsystem Version: "<<optHeader.MinorSubsystemVersion<<endl;
			cout<<"Size Of Image: "<<optHeader.SizeOfImage<<endl;
			cout<<"Size Of Headers: "<<optHeader.SizeOfHeaders<<endl;
			cout<<"CheckSum: "<<optHeader.CheckSum<<endl;
			cout<<"Subsystem: "<<optHeader.Subsystem<<endl;
			cout<<"Dll Characteristics: "<<optHeader.DllCharacteristics<<endl;
			cout<<"Size Of Stack Reserve: "<<optHeader.SizeOfStackReserve<<endl;
			cout<<"Size Of Stack Commit: "<<optHeader.SizeOfStackCommit<<endl;
			cout<<"Size Of Heap	Reserve: "<<optHeader.SizeOfHeapReserve<<endl;
			cout<<"Size Of Heap Commit: "<<optHeader.SizeOfHeapCommit<<endl;
			cout<<"Loader Flags: "<<optHeader.LoaderFlags<<endl;
			cout<<"Number Of Rva And Sise : "<<optHeader.NumberOfRvaAndSizes<<endl;
		}
};
			
class sec_header
{
public:
		IMAGE_SECTION_HEADER secHeader;
		int NoOfSec;
		int fp;

		sec_header(int f)
		{
			IMAGE_FILE_HEADER fileHeader;
			fp=f;
			_lseek(fp,OffFileHeader,0);
		    _read(f,&fileHeader,sizeof(fileHeader)); 
			NoOfSec = fileHeader.NumberOfSections;

			_lseek(f,OffSetHeader,0);
			_read(f,&secHeader,sizeof(secHeader));
		}
		void show_header()
		{
			cout<<endl<<"----------------SECTION HEADER INFO-----------"<<endl;
			while(NoOfSec!=0)
			{
				cout<<"Name: "<<secHeader.Name<<endl;
				cout<<"Virtual Address: "<<secHeader.VirtualAddress<<endl;
				cout<<"Size Of Raw Data: "<<secHeader.SizeOfRawData<<endl;
				cout<<"Pointer To Raw Data: "<<secHeader.PointerToRawData<<endl;
				cout<<"Pointer To Relocations:  "<<secHeader.PointerToRelocations<<endl;
				cout<<"Pointer To Line numbers: "<<secHeader.PointerToLinenumbers<<endl;
				cout<<"Number Of Relocations:  "<<secHeader.NumberOfRelocations<<endl;
				cout<<"Number Of Line numbers: "<<secHeader.NumberOfLinenumbers<<endl;
				cout<<"Characteristics: "<<secHeader.Characteristics<<endl;
				NoOfSec--;
				cout<<endl<<"-----------------------------------------------------"<<endl;
				_read(fp,&secHeader,sizeof(secHeader));
			}
		}
};
int main(int argc,char* argv[])
{
	int ip;
	char file_name[100];
	cout<<"enter the name of the file : ";
	cin>>file_name;
	int fd =open(file_name,O_BINARY,S_IREAD);
	if(fd==-1)
	{
		cout<<endl<<"error:file not found."<<endl;
		return -1;
	}
	CalculateOffset(fd);

	do
	{
		ip=0;
		cout<<endl<<"enter your choice :"<<endl;
		cout<<"1.Dos Header :"<<endl;
		cout<<"2.File Header :"<<endl;
		cout<<"3.Optional Header :"<<endl;
		cout<<"4.Section Header :"<<endl;
		cout<<"5.exit :"<<endl;
		cout<<"your choice :"<<endl;
		cin>>ip;
		switch(ip)
		{
				case 1:
				{
					dos_header dh(fd);
					dh.show_header();
					break;
				}
				case 2:
				{
					file_header dh(fd);
					dh.show_header();
					break;
				}
				case 3:
				{
					opt_header dh(fd);
					dh.show_header();
					break;
				}
				case 4:
				{
					sec_header dh(fd);
					dh.show_header();
					break;
				}
				case 5:
				{
					exit(0);
					break;
				}
		       default:break;
		}
	}while((ip!=5));
		return 0;
}
