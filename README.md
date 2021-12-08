# Doge-MemX
Golang implementation of Reflective load PE from memory

Only Supports x64 unmanaged PE

## Usage
- change black list https://github.com/timwhitez/Doge-MemX/blob/main/main.go#L269
```
blacklist := []string{
		//warning!! may cause panic!
		}
```

- change arguments https://github.com/timwhitez/Doge-MemX/blob/main/main.go#L324
```
tmpArgs := []string{"coffee"}
```

- go build

- run
```
Usage:
        Doge-MemX.exe mimikatz.exe
        
```

## ref
https://github.com/frkngksl/Huan
https://github.com/ayoul3/reflect-pe
https://github.com/Binject/debug
https://github.com/Binject/universal
