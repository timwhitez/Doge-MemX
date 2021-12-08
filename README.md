![Doge-Assembly](https://socialify.git.ci/timwhitez/Doge-MemX/image?description=1&font=Raleway&forks=1&issues=1&language=1&logo=https%3A%2F%2Favatars1.githubusercontent.com%2Fu%2F36320909&owner=1&pattern=Circuit%20Board&stargazers=1&theme=Light)

- 🐸Frog For Automatic Scan

- 🐶Doge For Defense Evasion & Offensive Security

# Doge-MemX
Golang implementation of Reflective load PE from memory

Only Supports x64 unmanaged PE

## Usage
- change black list https://github.com/timwhitez/Doge-MemX/blob/main/main.go#L313
```
blacklist := []string{
		//warning!! may cause panic!
		}
```

- change arguments https://github.com/timwhitez/Doge-MemX/blob/main/main.go#L368
```
tmpArgs := []string{"coffee"}
```

- new Thread or not https://github.com/timwhitez/Doge-MemX/blob/main/main.go#L372
```
//peLoader(&shellcode,"syscall")
peLoader(&shellcode,"createthread")
```

- go build

- run
```
Usage:
        Doge-MemX.exe mimikatz.exe
        
```

## Limitations
Reflect-pe only works for x64 dynamic executables.  

Reflect-pe only works for x64 unmanaged PE

It's not stable.

## References
https://github.com/frkngksl/Huan

https://github.com/ayoul3/reflect-pe

https://github.com/Binject/debug

https://github.com/Binject/universal

# 🚀Star Trend
[![Stargazers over time](https://starchart.cc/timwhitez/Doge-MemX.svg)](https://starchart.cc/timwhitez/Doge-MemX)

