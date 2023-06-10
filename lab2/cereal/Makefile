json_fuzzer:
	g++ -std=c++17 -c -Icereal/include json_fuzzer.cpp
	#clang++ -std=c++17 -c -Icereal/include -fsanitize=fuzzer json_fuzzer.cpp
	g++ json_fuzzer.o -o json_fuzzer
	#clang++ -fsanitize=fuzzer json_fuzzer.o -o json_fuzzer

clean:
	rm -f *.o json_fuzzer
