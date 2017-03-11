:: Build script for srtp_decoder for OS X and Linux
:: v0.1
@ECHO OFF

set destdir=.build
set libsdir=.usr

@if exist unzip.exe (
	unzip.exe .\win32\WpdPack_4_1_2.zip .. 
)
@if not exist WpdPack (
	echo Please, first unzip file: .\win32_vs15\WpdPack_4_1_2.zip
	exit /b 1
)

@if not exist libsrtp\Debug (
	echo Please, first build libsrtp library
	exit /b 1
)
@if not exist libsrtp\Release (
	echo Please, first build libsrtp library
	exit /b 1
)

@if not exist %destdir% (
	mkdir %destdir%
)

@if not exist %libsdir% (
	mkdir %libsdir%
)

:: Install libsrtp
cd libsrtp
call install-win.bat ..\\%libsdir%
cd ..

:: Generate srtp_decoder.h
cd .\.build
cmake ..
cd ..

echo Now you can build srtp_decoder, using Visual Studio solution
