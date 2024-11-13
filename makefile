all:
	gcc main.c -o main -lX11 -ljpeg -lcrypto -lssl
clean:
	rm -f main screenshot.jpg screenshot_encrypted.jpg example_encrypted.txt