
## Overflow WeChat Libpag CVE-2024-31734 
Overview:
wechat uses a libary for image procsessing called Libpag, which is in the current Android apk:
```
libpag.so
```
Upon some investigation we can get the libay from 
https://github.com/Tencent/libpag/tree/

after making the libary we can directly load it with some objective c code:
```c
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <objc/objc.h>
#include <objc/runtime.h>
// Define a function to load the image using the dynamic library
void load(NSString *path) {
    void *handle;
    char *error;
    // Open the dynamic library
    handle = dlopen("libpag", RTLD_LAZY);
    if (!handle) {
        NSLog(@"Error opening shared library: %s", dlerror());
        return;
    }
    // Get the class object for PAGFile
    Class PAGFileClass = objc_getClass("PAGFile");
    if (!PAGFileClass) {
        NSLog(@"Failed to get class PAGFile");
        dlclose(handle);
        return;
    }
    // Get the method signature for the Load: method
    SEL loadSelector = NSSelectorFromString(@"Load:");
    Method loadMethod = class_getClassMethod(PAGFileClass, loadSelector);
    if (!loadMethod) {
        NSLog(@"Failed to get method Load:");
        dlclose(handle);
        return;
    }
    // Get the function pointer for the Load: method
    IMP loadFunction = method_getImplementation(loadMethod);
    ((void (*)(id, SEL, NSString *))loadFunction)(PAGFileClass, loadSelector, path);
    // Close the dynamic library
    dlclose(handle);
}
int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            NSLog(@"Usage: %s <image_path>", argv[0]);
            return 1;
        }
        // Convert C string to NSString
        NSString *path = [NSString stringWithUTF8String:argv[1]];
        // Call the fuzz function to load the image using the dynamic library
        load(path);
    }
    return 0;
}
```
```bash
$ ./load test.png 
=================================================================
==11405==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x000107206082 at pc 0x000104f21f68 bp 0x00016b74abd0 sp 0x00016b74a390
READ of size 7 at 0x000107206082 thread T0
    #0 0x104f21f64 in wrap_strlen+0x264 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x15f64)
    #1 0x108ca1218 in pag::DecodeStream::readUTF8String()+0x3c (libpag:arm64+0x61218)
    #2 0x108c79014 in pag::ReadFontTables(pag::DecodeStream*)+0x60 (libpag:arm64+0x39014)
    #3 0x108c76f24 in std::__1::function<void (pag::DecodeStream*, pag::CodecContext*)>::operator()(pag::DecodeStream*, pag::CodecContext*) const+0x28 (libpag:arm64+0x36f24)
    #4 0x108c76ee8 in pag::ReadTagsOfFile(pag::DecodeStream*, pag::TagCode, pag::CodecContext*)+0x3c (libpag:arm64+0x36ee8)
    #5 0x108c53f10 in pag::Codec::Decode(void const*, unsigned int, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x11c (libpag:arm64+0x13f10)
    #6 0x108c442ac in pag::File::Load(void const*, unsigned long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x16c (libpag:arm64+0x42ac)
    #7 0x108c440f0 in pag::File::Load(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x34 (libpag:arm64+0x40f0)
    #8 0x108cf7de8 in pag::PAGFile::Load(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x18 (libpag:arm64+0xb7de8)
    #9 0x108ca8164 in +[PAGFileImpl Load:]+0xfc (libpag:arm64+0x68164)
    #10 0x1046b79fc in fuzz load.m:40
    #11 0x1046b7ae8 in main load.m:57
    #12 0x1833a50dc  (<unknown module>)

0x000107206082 is located 0 bytes after 18-byte region [0x000107206070,0x000107206082)
allocated by thread T0 here:
    #0 0x104f6da94 in wrap__ZnamRKSt9nothrow_t+0x74 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x61a94)
    #1 0x108c4222c in pag::ByteData::Make(unsigned long)+0x40 (libpag:arm64+0x222c)
    #2 0x108c42118 in pag::ByteData::FromPath(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x38 (libpag:arm64+0x2118)
    #3 0x108c440d8 in pag::File::Load(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x1c (libpag:arm64+0x40d8)
    #4 0x108cf7de8 in pag::PAGFile::Load(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)+0x18 (libpag:arm64+0xb7de8)
    #5 0x108ca8164 in +[PAGFileImpl Load:]+0xfc (libpag:arm64+0x68164)
    #6 0x1046b79fc in fuzz load.m:40
    #7 0x1046b7ae8 in main load.m:57
    #8 0x1833a50dc  (<unknown module>)

SUMMARY: AddressSanitizer: heap-buffer-overflow (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x15f64) in wrap_strlen+0x264
Shadow bytes around the buggy address:
  0x000107205e00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x000107205e80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x000107205f00: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x000107205f80: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x000107206000: fa fa fa fa fa fa fa fa fa fa fa fa fa fa 00 00
=>0x000107206080:[02]fa fa fa fd fd fd fa fa fa 00 00 00 00 fa fa
  0x000107206100: 00 00 00 00 fa fa 00 00 00 00 fa fa 00 00 00 00
  0x000107206180: fa fa 00 00 00 00 fa fa 00 00 00 00 fa fa fd fd
  0x000107206200: fd fd fa fa fd fd fd fd fa fa 00 00 00 00 fa fa
  0x000107206280: 00 00 00 00 fa fa 00 00 00 00 fa fa 00 00 00 00
  0x000107206300: fa fa 00 00 00 00 fa fa 00 00 00 00 fa fa 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==11405==ABORTING
```
The DecodeStream::readUTF8String() function in the provided code snippet is susceptible to a heap buffer overflow due to the improper use of the strlen() function. This vulnerability arises when processing input data, leading to potential security risks.

Vulnerability Description:
The vulnerability occurs in the following line of code:

```c 
std::string DecodeStream::readUTF8String() {
  if (_position < dataView.size()) {
    auto text = reinterpret_cast<const char*>(dataView.bytes() + _position);
    auto textLength = strlen(text);
    if (textLength > dataView.size() - _position) {
      textLength = dataView.size() - _position;
      positionChanged(static_cast<off_t>(textLength));
    } else {
      positionChanged(static_cast<off_t>(textLength + 1));
    }
    return {text, textLength};
  } else {
    PAGThrowError(context, "End of file was encountered.");
  }
  return "";
}
```

auto textLength = strlen(text);

Here, the strlen() function is used to determine the length of the string pointed to by the 'text' pointer. However, if the string pointed to by 'text' is not properly null-terminated or contains embedded null characters within the expected string length, strlen() will continue scanning memory until it encounters a null terminator ('\0'). This behavior may cause strlen() to read beyond the allocated memory region of the 'dataView', leading to a heap buffer overflow.

Impact:
If exploited, this heap buffer overflow vulnerability could allow an attacker to execute arbitrary code, modify data, or crash the application, potentially compromising the security and integrity of the system. Since heap overflows can be exploited to achieve remote code execution or escalate privileges, this vulnerability poses a significant security risk.

Recommendations:
To mitigate this vulnerability, the following steps are recommended:

    Input Validation: Ensure that input data passed to the DecodeStream::readUTF8String() function is properly validated and sanitized to prevent malicious input from triggering the heap overflow.
    Boundary Checking: Implement proper boundary checks to ensure that the strlen() function does not read beyond the bounds of the allocated memory region of 'dataView'.
    Use Safe String Functions: Consider using safer alternatives to strlen() for string manipulation, such as std::string member functions or functions that explicitly handle string lengths and boundaries.
    Code Review and Testing: Conduct thorough code reviews and testing to identify and remediate similar vulnerabilities in other parts of the codebase.
    Security Awareness: Educate developers about secure coding practices, buffer overflow vulnerabilities, and the importance of input validation and boundary checking to prevent such security issues.

Conclusion:
The presence of a heap buffer overflow vulnerability in the DecodeStream::readUTF8String() function poses a significant risk to the security of the application. By following the recommended mitigations and best practices, developers can reduce the likelihood of exploitation and enhance the overall security posture of the software.

This report highlights the critical need for proactive vulnerability management and secure coding practices to address and mitigate security risks effectively.


Patch is here https://github.com/Tencent/libpag/pull/2232 
