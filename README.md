# alumini
> Run command-line go32-extended DOS applications natively on linux

## Getting started
```
rustup target add i686-unknown-linux-gnu
git clone https://github.com/ConorBobbleHat/alumini && cd alumini
cargo build
sudo target/i686-unknown-linux-gnu/release/alumini <program> [arguments] 
```

## Disclaimer
alumini requires elevated privileges to run - go32 executables presume they're running near the top of their virtual address space, which linux requires `CAP_RAW_IO` to achieve.

If using experimental software to run decades-old programs on your system didn't give you pause, the fact they're running with root privileges absolutely should! Please DO NOT run this on any untrusted programs!