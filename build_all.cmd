:: Build script for srtp_decoder for OS X and Linux
:: v0.1

set destdir=.build
set libsdir=.usr

@if exist %destdir% (
	rmdir %destdir%
)
mkdir %destdir%

@if exist %libsdir% (
	rmdir %libsdir%
)
mkdir %libsdir%

cd libsrtp
install-win.bat ..\\%libsdir%
cd ..

:: Generate srtp_decoder.h
cd .build
cmake ..
cd ..

echo "Now you can build srtp_decoder"
